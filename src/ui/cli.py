import logging
import shlex
import time
import os
from typing import Optional

from src.data import database
from src.core import app, auth
from src.core.crypto import RateLimiter
from src.core.session_manager import SessionManager
from src.ui import views, parser, colors, commands
from src.utils.validators import InputValidator
from src.config import Config

# Global rate limiter for login attempts
_rate_limiter = RateLimiter()


def setup_logging():
    """
    Configure logging to file within application storage directory.

    Creates log file in ~/.cypher/cypher_activity.log with timestamps.
    """
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
    Run continuous interactive command loop for loaded profile.

    Features:
    - Command parsing and execution
    - Session timeout monitoring
    - Auto-save on commands
    - Graceful error handling

    Args:
        app_session: Active application session with loaded profile

    Returns:
        'SWITCH' to return to profile selection, 'EXIT' to quit application
    """
    # Initialize command parser
    arg_parser = parser.initialize_parser()

    # Setup session timeout manager
    session_manager: Optional[SessionManager] = None
    session_active = True

    def on_session_timeout():
        """Handle session timeout."""
        nonlocal session_active
        session_active = False
        print(
            f"\n{colors.Colors.WARNING}⚠ Session timed out due to inactivity "
            f"({Config.SESSION_TIMEOUT_SECONDS // 60} minutes){colors.Colors.RESET}"
        )
        logging.info(f"Session timeout for profile: {app_session.profile_name}")

    def cleanup_session():
        """Cleanup on timeout."""
        try:
            if app_session.is_profile_loaded():
                app_session.save_profile()
                logging.info("Profile auto-saved on timeout")
        except Exception as e:
            logging.error(f"Error saving profile on timeout: {e}")

    # Start session manager
    session_manager = SessionManager(
        on_timeout=on_session_timeout, cleanup_callback=cleanup_session
    )
    session_manager.start()

    # Display UI
    views.clear_screen()
    views.show_banner()

    if app_session.profile_name:
        views.show_profile_header(app_session.profile_name)
        print(
            f"\n{colors.Colors.SUCCESS}✓ Logged in successfully!{colors.Colors.RESET}\n"
        )

    views.show_quick_help()

    # Available commands for suggestion
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
        "export",
    ]

    try:
        while session_active:
            try:
                # Reset session timeout on each interaction
                if session_manager:
                    session_manager.reset_timer()

                # Display prompt
                prompt = (
                    f"{colors.Colors.PROMPT}cypher"
                    f"{colors.Colors.RESET}@{colors.Colors.SUCCESS}{app_session.profile_name}"
                    f"{colors.Colors.RESET} {colors.Colors.PRIMARY}❯{colors.Colors.RESET} "
                )
                raw_input = input(prompt).strip()

                # Skip empty input
                if not raw_input:
                    continue

                # Check for quick exit commands
                lower_input = raw_input.lower()
                if lower_input in ("exit", "quit", "q"):
                    return "EXIT"
                if lower_input in ("switch", "reload", "restart"):
                    return "SWITCH"

                # Parse command with shlex (handles quoted arguments)
                try:
                    split_input = shlex.split(raw_input)
                except ValueError as e:
                    # Handle unclosed quotes, etc.
                    views.show_error(f"Invalid command syntax: {e}")
                    logging.warning(f"Command syntax error: {e}")
                    continue

                # Parse arguments with argparse
                try:
                    args = arg_parser.parse_args(split_input)

                    if hasattr(args, "func"):
                        # Check for special commands
                        if args.func == commands.switch_command:
                            return "SWITCH"

                        # Execute command
                        args.func(args, app_session)

                        # Auto-save after each command (except read-only operations)
                        if args.func not in [
                            commands.get_command,
                            commands.list_command,
                            commands.search_command,
                            commands.clear_command,
                        ]:
                            try:
                                app_session.save_profile()
                            except Exception as e:
                                logging.error(f"Auto-save failed: {e}")
                    else:
                        # No function associated, suggest similar command
                        if split_input:
                            views.suggest_command(split_input[0], available_commands)

                except SystemExit:
                    # argparse calls sys.exit() on error, catch it
                    pass
                except KeyboardInterrupt:
                    # Propagate interrupt to outer handler
                    raise
                except Exception as e:
                    # Catch-all for command execution errors
                    views.show_error(f"Command error: {e}")
                    logging.exception(f"Command execution error: {e}")

            except KeyboardInterrupt:
                # User pressed Ctrl+C
                print()  # New line after ^C
                confirm = input(
                    f"{colors.Colors.WARNING}Exit to profile selection? (y/N): {colors.Colors.RESET}"
                ).lower()
                if confirm == "y":
                    return "SWITCH"
                # Otherwise continue loop

    except Exception as e:
        # Unexpected error in main loop
        logging.exception(f"Unexpected error in interactive shell: {e}")
        views.show_error(f"An unexpected error occurred: {e}")
        return "EXIT"

    finally:
        # Always stop session manager
        if session_manager:
            session_manager.stop()

    return "EXIT"


def start_application():
    """
    Main application entry point - Production ready.

    Flow:
    1. Setup logging
    2. Check if first run (setup required)
    3. Unlock session with device token
    4. Profile selection loop
    5. Interactive shell for active profile
    6. Graceful cleanup on exit
    """
    app_session: Optional[app.App] = None

    try:
        # Initialize logging
        setup_logging()
        logging.info("Application starting")

        views.clear_screen()

        # First-time setup check
        if database.is_first_ever_run():
            views.show_banner()
            print(
                f"\n{colors.Colors.INFO}First-time setup required{colors.Colors.RESET}\n"
            )
            auth.initial_setup()
            views.show_info("Please restart Cypher to begin.")
            logging.info("First-time setup completed")
            return

        # Normal startup - unlock session
        views.show_banner()
        views.show_loading("Initializing secure session")

        session_god_key, profiles_conn = auth.unlock_session()
        views.clear_loading()

        if not session_god_key or not profiles_conn:
            views.show_error("Failed to unlock session.")
            logging.error("Session unlock failed")
            return

        logging.info("Session unlocked successfully")
        views.show_success("Session unlocked")
        time.sleep(Config.LOADING_DISPLAY_DURATION)

        # Create application session
        app_session = app.App(profiles_conn, session_god_key)

        # Profile selection loop
        while True:
            # Clear screen for profile selection
            views.clear_screen()
            views.show_banner()

            # Display available profiles
            all_profiles = database.get_all_profile_names(profiles_conn)

            if all_profiles:
                # Limit display to prevent terminal overflow
                if len(all_profiles) > 50:
                    views.show_warning(
                        f"You have {len(all_profiles)} profiles. Showing first 50..."
                    )
                    views.display_profile_list(all_profiles[:50])
                else:
                    views.display_profile_list(all_profiles)

            # Prompt for profile selection
            print(
                f"\n{colors.Colors.INFO}Enter a profile name to login or create a new one."
            )
            print(f"Press Enter to exit.{colors.Colors.RESET}\n")

            profile_name_input = views.prompt_input("Profile name:")

            # Empty input = exit
            if not profile_name_input:
                logging.info("User chose to exit")
                break

            # Validate and sanitize profile name
            profile_name = profile_name_input.lower().strip()
            valid, msg = InputValidator.validate_profile_name(profile_name)

            if not valid:
                views.show_error(msg)
                logging.warning(f"Invalid profile name: {profile_name}")
                time.sleep(Config.ERROR_DISPLAY_DURATION)
                continue

            # Rate limiting check
            allowed, wait_time = _rate_limiter.check_attempt(profile_name)

            if not allowed:
                views.show_error(
                    f"Too many failed attempts for '{profile_name}'. "
                    f"Please wait {wait_time} seconds."
                )
                logging.warning(f"Rate limit hit for profile: {profile_name}")
                time.sleep(Config.ERROR_DISPLAY_DURATION)
                continue

            # Check if profile exists
            profile_details = database.get_profile_details(profiles_conn, profile_name)

            if not profile_details:
                # NEW PROFILE - Create it
                print(
                    f"\n{colors.Colors.WARNING}Creating new profile "
                    f"'{profile_name}'...{colors.Colors.RESET}"
                )

                master_password = commands.create_new_profile_flow(profile_name)

                if not master_password:
                    # User cancelled profile creation
                    logging.info(f"Profile creation cancelled: {profile_name}")
                    time.sleep(Config.LOADING_DISPLAY_DURATION)
                    continue

                try:
                    # Create profile
                    print(
                        f"{colors.Colors.INFO}⟳ Setting up profile...{colors.Colors.RESET}",
                        end="",
                        flush=True,
                    )

                    success = app_session.load_user_profile(
                        profile_name, master_password
                    )

                    # Clear progress indicator
                    print("\r" + " " * 50 + "\r", end="", flush=True)

                    if success:
                        _rate_limiter.reset(profile_name)
                        views.show_success(f"Profile '{profile_name}' created!")
                        logging.info(f"New profile created: {profile_name}")
                        time.sleep(Config.SUCCESS_DISPLAY_DURATION)
                    else:
                        views.show_error("Failed to create profile.")
                        logging.error(f"Profile creation failed: {profile_name}")
                        time.sleep(Config.ERROR_DISPLAY_DURATION)
                        continue

                except Exception as e:
                    # Clear progress indicator
                    print("\r" + " " * 50 + "\r", end="", flush=True)
                    views.show_error(f"Error creating profile: {e}")
                    logging.exception(f"Profile creation error: {profile_name}")
                    time.sleep(Config.ERROR_DISPLAY_DURATION)
                    continue

            else:
                # EXISTING PROFILE - Login
                print(
                    f"\n{colors.Colors.WARNING}Logging in to "
                    f"'{profile_name}'...{colors.Colors.RESET}"
                )

                try:
                    if not commands.login_flow(app_session, profile_name):
                        # Login failed - user will see error message
                        logging.warning(f"Login failed for profile: {profile_name}")
                        time.sleep(Config.ERROR_DISPLAY_DURATION)
                        continue

                    # Success - reset rate limiter
                    _rate_limiter.reset(profile_name)
                    logging.info(f"Login successful: {profile_name}")

                except Exception as e:
                    views.show_error(f"Login error: {e}")
                    logging.exception(f"Login error for {profile_name}")
                    time.sleep(Config.ERROR_DISPLAY_DURATION)
                    continue

            # Start interactive shell for logged-in profile
            try:
                action = start_interactive_shell(app_session)

                # Unload profile (saves and clears from memory)
                app_session.unload_profile()
                logging.info(f"Profile unloaded: {profile_name}")

                # Check return action
                if action == "EXIT":
                    logging.info("User chose to exit application")
                    break
                # Otherwise, continue to profile selection (SWITCH)

            except Exception as e:
                views.show_error(f"Error in interactive shell: {e}")
                logging.exception("Interactive shell error")

                # Attempt to unload profile safely
                try:
                    app_session.unload_profile()
                except Exception as unload_error:
                    logging.error(f"Error unloading profile: {unload_error}")

                time.sleep(Config.ERROR_DISPLAY_DURATION)
                continue

    except KeyboardInterrupt:
        # User interrupted with Ctrl+C
        print(
            f"\n\n{colors.Colors.WARNING}Session interrupted by user.{colors.Colors.RESET}"
        )
        logging.info("Session interrupted by user (Ctrl+C)")

    except Exception as e:
        # Critical unexpected error
        views.show_error(f"A critical error occurred: {e}")
        logging.exception("Critical error in main execution loop")

    finally:
        # Always attempt cleanup
        if app_session:
            try:
                app_session.close_and_save_session()
                logging.info("Session closed successfully")
            except Exception as e:
                logging.error(f"Error closing session: {e}")

        logging.info("Application shutdown")


if __name__ == "__main__":
    start_application()
