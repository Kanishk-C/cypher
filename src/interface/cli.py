"""Enhanced CLI with rate limiting and improved UX."""

import logging
import shlex
import time
import os
from data import database
from core import core, auth
from core.security import RateLimiter
from . import views, parser, colors, handlers


# Global rate limiter
_rate_limiter = RateLimiter()


def setup_logging():
    """Configures logging to a file within the application's storage directory."""
    storage_dir = database.get_storage_directory()
    log_file_path = os.path.join(storage_dir, "cypher_activity.log")
    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def start_interactive_shell(app: core.App) -> str:
    """
    Runs the continuous interactive command loop for a loaded profile.
    Returns 'SWITCH' or 'EXIT'.
    """
    arg_parser = parser.initialize_parser()
    views.clear_screen()
    views.show_banner()
    views.show_profile_header(app.profile_name)

    # Show vault statistics
    try:
        entries = app.list_all_entries()
        services = set(service for service, _ in entries)
        views.show_stats(len(entries), len(services))
        if entries:
            views.show_recent_activity(entries, limit=5)
    except:
        pass

    views.show_quick_help()

    # Available commands for suggestions
    available_commands = [
        'add', 'a', 'get', 'g', 'list', 'l', 'delete', 'd',
        'update', 'u', 'search', 's', 'clear', 'cls', 'c',
        'help', 'h', '?', 'switch', 'reload', 'restart',
        'exit', 'quit', 'q', 'stats', 'statistics', 'info', 'generate', 'gen'
    ]

    while True:
        try:
            # Enhanced prompt
            prompt = f"{colors.Colors.BRIGHT_CYAN}cypher{colors.Colors.RESET}@{colors.Colors.BRIGHT_GREEN}{app.profile_name}{colors.Colors.RESET} {colors.Colors.BRIGHT_BLUE}❯{colors.Colors.RESET} "
            raw_input = input(prompt).strip()

            if not raw_input:
                continue

            lower_input = raw_input.lower()
            first_word = lower_input.split()[0] if ' ' in lower_input else lower_input

            if lower_input in ("exit", "quit", "q"):
                return 'EXIT'

            if lower_input in ("switch", "reload", "restart"):
                return 'SWITCH'

            if lower_input in ("help", "h", "?"):
                arg_parser.print_help()
                print()
                continue

            if lower_input in ("clear", "cls", "c"):
                views.clear_screen()
                views.show_banner()
                views.show_profile_header(app.profile_name)
                try:
                    entries = app.list_all_entries()
                    services = set(service for service, _ in entries)
                    views.show_stats(len(entries), len(services))
                    if entries:
                        views.show_recent_activity(entries, limit=5)
                except:
                    pass
                views.show_quick_help()
                continue

            if lower_input in ("stats", "statistics", "info"):
                entries = app.list_all_entries()
                services = set(service for service, _ in entries)
                views.show_stats(len(entries), len(services))
                if entries:
                    views.show_recent_activity(entries, limit=10)
                views.wait_for_user()
                continue

            # Parse and execute commands
            try:
                split_input = shlex.split(raw_input)
                args = arg_parser.parse_args(split_input)

                if hasattr(args, "func"):
                    if args.func == handlers.switch_command:
                        return 'SWITCH'
                    args.func(args, app)
                else:
                    views.suggest_command(first_word, available_commands)

            except SystemExit:
                pass
            except ValueError as e:
                views.show_error(f"Invalid command format: {e}")
                views.suggest_command(first_word, available_commands)

        except KeyboardInterrupt:
            print()
            return 'EXIT'

        except Exception as e:
            logging.exception(f"Unexpected error in main loop: {e}")
            views.show_error("An unexpected error occurred")
            views.show_info("Details have been logged to the .cypher directory")
            print()

    return 'EXIT'


def start_application():
    """Main application entry point with rate limiting."""
    app_session = None

    try:
        setup_logging()
        views.clear_screen()

        # First-time setup
        if database.is_first_ever_run():
            views.show_banner()
            auth.initial_setup()
            views.show_info("Please restart Cypher to begin using it")
            return

        # Unlock session
        views.show_banner()
        views.show_loading("Initializing secure session")
        session_god_key, profiles_conn = auth.unlock_session()
        views.clear_loading()

        if not session_god_key or not profiles_conn:
            views.show_error("Failed to unlock session")
            logging.warning("Session unlock failed")
            return

        logging.info("Application unlocked successfully")
        views.show_success("Session unlocked")
        app_session = core.App(profiles_conn, session_god_key)

        # Profile selection loop
        while True:
            views.clear_screen()
            views.show_banner()
            
            # --- New Feature: List existing profiles ---
            all_profiles = database.get_all_profile_names(profiles_conn)
            if all_profiles:
                views.display_profile_list(all_profiles)
            
            print(f"{colors.Colors.BRIGHT_BLUE}Enter a profile name to login or create a new one.")
            print(f"Press Enter (empty) to exit Cypher.{colors.Colors.RESET}\n")

            profile_name = views.prompt_input("Profile name:").lower()

            if not profile_name:
                break

            # Rate limiting check
            allowed, wait_time = _rate_limiter.check_attempt(profile_name)
            if not allowed:
                views.show_error(f"Too many failed attempts for '{profile_name}'")
                views.show_info(f"Please wait {wait_time} seconds before trying again")
                time.sleep(2)
                continue

            # Check if profile exists
            profile_details = database.get_profile_details(profiles_conn, profile_name)

            if not profile_details:
                # New profile creation
                views.clear_screen()
                views.show_banner()
                views.show_section_header(f"Create New Profile: {profile_name}")
                print(f"{colors.Colors.BRIGHT_YELLOW}This profile doesn't exist yet. Let's create it!{colors.Colors.RESET}\n")

                from utils.validators import InputValidator
                from config import Config

                master_password = None
                while True:
                    p1 = views.prompt_password(f"Create master password (min {Config.MIN_MASTER_PASSWORD_LENGTH} characters):")

                    valid, msg = InputValidator.validate_password_strength(p1, Config.MIN_MASTER_PASSWORD_LENGTH)
                    if not valid:
                        views.show_warning(msg)
                        continue

                    p2 = views.prompt_password("Confirm master password:")

                    if p1 == p2:
                        master_password = p1
                        break
                    else:
                        views.show_error("Passwords do not match. Try again.")
                        print()

                # Load the new profile
                views.show_loading(f"Creating profile '{profile_name}'")
                if app_session.load_user_profile(profile_name, master_password):
                    views.clear_loading()
                    views.show_success(f"Profile '{profile_name}' created and loaded successfully")
                    _rate_limiter.reset(profile_name)
                    logging.info(f"Profile '{profile_name}' created and logged in successfully")
                else:
                    views.clear_loading()
                    views.show_error("Failed to create profile")
                    logging.warning(f"Failed to create profile: '{profile_name}'")
                    views.wait_for_user()
                    continue

            else:
                # Existing profile login
                print()
                max_attempts = 3
                attempt = 0
                master_password = None

                while attempt < max_attempts:
                    master_password = views.prompt_password(f"Master password for '{profile_name}':")

                    # Validate password
                    views.show_loading(f"Authenticating '{profile_name}'")
                    if app_session.load_user_profile(profile_name, master_password):
                        views.clear_loading()
                        views.show_success(f"Profile '{profile_name}' loaded successfully")
                        _rate_limiter.reset(profile_name)
                        logging.info(f"Profile '{profile_name}' logged in successfully")
                        break
                    else:
                        views.clear_loading()
                        attempt += 1
                        remaining = max_attempts - attempt
                        if remaining > 0:
                            views.show_error(f"Incorrect password. {remaining} attempt{'s' if remaining > 1 else ''} remaining")
                            print()
                        else:
                            views.show_error("Too many failed attempts. Returning to profile selection.")
                            logging.warning(f"Too many failed login attempts for profile: '{profile_name}'")
                            master_password = None
                            views.wait_for_user()

                if not master_password:
                    continue

            # Enter interactive shell
            action = start_interactive_shell(app_session)

            # Handle logout
            views.show_loading("Saving and locking profile")
            logging.info(f"Profile '{profile_name}' logged out")
            app_session.unload_profile()
            views.clear_loading()
            views.show_success("Profile saved and locked")

            if action == 'EXIT':
                break
            elif action == 'SWITCH':
                views.show_info("Switching profiles...")
                views.wait_for_user()

    except KeyboardInterrupt:
        print(f"\n\n{colors.Colors.BRIGHT_YELLOW}Session interrupted by user{colors.Colors.RESET}")

    except Exception as e:
        views.show_error(f"Critical error: {e}")
        logging.exception("Critical error in main execution loop")

    finally:
        if app_session:
            views.show_loading("Saving session data")
            app_session.close_and_save_session()
            views.clear_loading()