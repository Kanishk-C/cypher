import logging
import shlex
import time
import os
from src.data import database
from src.core import app, auth
from src.core.crypto import RateLimiter
from src.ui import views, parser, colors, commands
from src.utils.validators import InputValidator  # ADDED: Import validator
from src.config import Config  # ADDED: Import Config

_rate_limiter = RateLimiter()


def setup_logging():
    """Configures logging to a file within the application's storage directory."""
    storage_dir = database.get_storage_directory()
    log_file_path = os.path.join(storage_dir, "cypher_activity.log")

    os.makedirs(storage_dir, exist_ok=True)

    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def start_interactive_shell(app_session: app.App) -> str:
    """
    Runs the continuous interactive command loop for a loaded profile.
    Returns 'SWITCH' or 'EXIT'.
    """
    arg_parser = parser.initialize_parser()

    # Clear screen and show UI
    views.clear_screen()
    views.show_banner()

    if app_session.profile_name:
        views.show_profile_header(app_session.profile_name)
        print(
            f"\n{colors.Colors.SUCCESS}✓ Logged in successfully!{colors.Colors.RESET}\n"
        )

    views.show_quick_help()

    available_commands = [
        "add",
        "get",
        "list",
        "delete",
        "update",
        "search",
        "generate",
        "clear",
        "help",
        "switch",
        "exit",
        "delete-profile",
    ]

    while True:
        try:
            prompt = (
                f"{colors.Colors.PROMPT}cypher"
                f"{colors.Colors.RESET}@{colors.Colors.SUCCESS}{app_session.profile_name}"
                f"{colors.Colors.RESET} {colors.Colors.PRIMARY}❯{colors.Colors.RESET} "
            )
            raw_input = input(prompt).strip()

            if not raw_input:
                continue

            lower_input = raw_input.lower()
            if lower_input in ("exit", "quit", "q"):
                return "EXIT"
            if lower_input in ("switch", "reload", "restart"):
                return "SWITCH"

            try:
                split_input = shlex.split(raw_input)
                args = arg_parser.parse_args(split_input)
                if hasattr(args, "func"):
                    if args.func == commands.switch_command:
                        return "SWITCH"
                    args.func(args, app_session)
                else:
                    views.suggest_command(split_input[0], available_commands)
            except SystemExit:
                pass
            except ValueError as e:
                views.show_error(f"Invalid command format: {e}")

        except KeyboardInterrupt:
            print()
            return "EXIT"
        except Exception as e:
            logging.exception(f"Unexpected error in main loop: {e}")
            views.show_error(f"An unexpected error occurred: {e}")

    return "EXIT"


def start_application():
    """Main application entry point - FIXED VERSION with Config constants and validation."""
    app_session = None
    try:
        setup_logging()
        views.clear_screen()

        if database.is_first_ever_run():
            views.show_banner()
            auth.initial_setup()
            views.show_info("Please restart Cypher to begin.")
            return

        views.show_banner()
        views.show_loading("Initializing secure session")
        session_god_key, profiles_conn = auth.unlock_session()
        views.clear_loading()

        if not session_god_key or not profiles_conn:
            views.show_error("Failed to unlock session.")
            return

        logging.info("Application unlocked successfully.")
        views.show_success("Session unlocked")
        time.sleep(Config.LOADING_DISPLAY_DURATION)  # FIXED: Use Config constant

        app_session = app.App(profiles_conn, session_god_key)

        while True:
            # Only clear screen when returning to profile selection
            views.clear_screen()
            views.show_banner()

            all_profiles = database.get_all_profile_names(profiles_conn)
            if all_profiles:
                views.display_profile_list(all_profiles)

            print(
                f"{colors.Colors.INFO}Enter a profile name to login or create a new one."
            )
            print(f"Press Enter to exit.{colors.Colors.RESET}\n")

            profile_name_input = views.prompt_input("Profile name:")
            if not profile_name_input:
                break

            # FIXED: Validate and sanitize profile name
            profile_name = profile_name_input.lower().strip()
            valid, msg = InputValidator.validate_profile_name(profile_name)
            if not valid:
                views.show_error(msg)
                time.sleep(Config.ERROR_DISPLAY_DURATION)  # FIXED: Use Config constant
                continue

            # Rate limiting
            allowed, wait_time = _rate_limiter.check_attempt(profile_name)
            if not allowed:
                views.show_error(
                    f"Too many failed attempts for '{profile_name}'. Please wait {wait_time} seconds."
                )
                time.sleep(Config.ERROR_DISPLAY_DURATION)  # FIXED: Use Config constant
                continue

            profile_details = database.get_profile_details(profiles_conn, profile_name)

            if not profile_details:
                # NEW PROFILE - Create it
                print(
                    f"\n{colors.Colors.WARNING}Creating new profile '{profile_name}'...{colors.Colors.RESET}"
                )
                master_password = commands.create_new_profile_flow(profile_name)
                if not master_password:
                    time.sleep(
                        Config.LOADING_DISPLAY_DURATION
                    )  # FIXED: Use Config constant
                    continue

                try:
                    print(
                        f"{colors.Colors.INFO}⟳ Setting up profile...{colors.Colors.RESET}",
                        end="",
                        flush=True,
                    )
                    success = app_session.load_user_profile(
                        profile_name, master_password
                    )
                    print("\r" + " " * 50 + "\r", end="", flush=True)

                    if success:
                        _rate_limiter.reset(profile_name)
                        views.show_success(f"Profile '{profile_name}' created!")
                        time.sleep(
                            Config.SUCCESS_DISPLAY_DURATION
                        )  # FIXED: Use Config constant
                    else:
                        views.show_error("Failed to create profile.")
                        time.sleep(
                            Config.ERROR_DISPLAY_DURATION
                        )  # FIXED: Use Config constant
                        continue
                except Exception as e:
                    print("\r" + " " * 50 + "\r", end="", flush=True)
                    views.show_error(f"Error creating profile: {e}")
                    logging.exception(f"Profile creation error")
                    time.sleep(
                        Config.ERROR_DISPLAY_DURATION
                    )  # FIXED: Use Config constant
                    continue
            else:
                # EXISTING PROFILE - Login
                print(
                    f"\n{colors.Colors.WARNING}Logging in to '{profile_name}'...{colors.Colors.RESET}"
                )
                try:
                    # FIXED: Don't clear screen before showing errors
                    if not commands.login_flow(app_session, profile_name):
                        # Login failed - give user time to read error
                        time.sleep(
                            Config.ERROR_DISPLAY_DURATION
                        )  # FIXED: Use Config constant
                        continue
                    _rate_limiter.reset(profile_name)
                except Exception as e:
                    views.show_error(f"Login error: {e}")
                    logging.exception(f"Login error")
                    time.sleep(
                        Config.ERROR_DISPLAY_DURATION
                    )  # FIXED: Use Config constant
                    continue

            # Start interactive shell ONLY after successful login
            try:
                action = start_interactive_shell(app_session)
                app_session.unload_profile()

                if action == "EXIT":
                    break
            except Exception as e:
                views.show_error(f"Error in interactive shell: {e}")
                logging.exception("Interactive shell error")
                app_session.unload_profile()
                time.sleep(Config.ERROR_DISPLAY_DURATION)  # FIXED: Use Config constant
                continue

    except KeyboardInterrupt:
        print(
            f"\n\n{colors.Colors.WARNING}Session interrupted by user.{colors.Colors.RESET}"
        )
    except Exception as e:
        views.show_error(f"A critical error occurred: {e}")
        logging.exception("Critical error in main execution loop.")
    finally:
        if app_session:
            app_session.close_and_save_session()
