"""Enhanced CLI with rate limiting and improved UX."""

import logging
import shlex
import time
import os
import gc
import threading
from src.data import database
from src.core import app, auth
from src.core.session_manager import SessionManager
from src.core.crypto import RateLimiter
from src.ui import views, parser, colors, commands

_rate_limiter = RateLimiter()
SESSION_TIMED_OUT = threading.Event()


def handle_timeout():
    """Callback function executed by the SessionManager on timeout."""
    SESSION_TIMED_OUT.set()


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


def start_interactive_shell(app_session: app.App) -> str:
    """
    Runs the continuous interactive command loop for a loaded profile.
    Returns 'SWITCH' or 'EXIT'.
    """

    def cleanup_on_timeout():
        """Force cleanup of sensitive data."""
        try:
            app_session.unload_profile()
        except:
            pass
        gc.collect()

    session_manager = SessionManager(
        on_timeout=handle_timeout, cleanup_callback=cleanup_on_timeout  # NEW
    )
    session_manager.start()

    arg_parser = parser.initialize_parser()
    views.clear_screen()
    views.show_banner()
    if app_session.profile_name:
        views.show_profile_header(app_session.profile_name)

    try:
        entries = app_session.list_all_entries()
        services = set(service for service, _ in entries)
        views.show_stats(len(entries), len(services))
        if entries:
            views.show_recent_activity(entries)
    except Exception:
        pass

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
        # Check for session timeout at the beginning of each loop
        if SESSION_TIMED_OUT.is_set():
            views.show_warning(
                "\nSession timed out due to inactivity. Profile has been locked."
            )
            session_manager.stop()
            return "SWITCH"  # Force re-authentication

        try:
            # Reset the inactivity timer with each user prompt
            session_manager.reset_timer()

            prompt = (
                f"{colors.Colors.BRIGHT_CYAN}cypher"
                f"{colors.Colors.RESET}@{colors.Colors.BRIGHT_GREEN}{app_session.profile_name}"
                f"{colors.Colors.RESET} {colors.Colors.BRIGHT_BLUE}❯{colors.Colors.RESET} "
            )
            raw_input = input(prompt).strip()

            if not raw_input:
                continue

            lower_input = raw_input.lower()
            if lower_input in ("exit", "quit", "q"):
                session_manager.stop()  # Stop timer on exit
                return "EXIT"
            if lower_input in ("switch", "reload", "restart"):
                session_manager.stop()  # Stop timer on switch
                return "SWITCH"

            try:
                split_input = shlex.split(raw_input)
                args = arg_parser.parse_args(split_input)
                if hasattr(args, "func"):
                    if args.func == commands.switch_command:
                        session_manager.stop()
                        return "SWITCH"
                    args.func(args, app_session)
                else:
                    views.suggest_command(split_input[0], available_commands)
            except SystemExit:
                pass
            except ValueError as e:
                views.show_error(f"Invalid command format: {e}")

        except KeyboardInterrupt:
            session_manager.stop()  # Stop timer on interrupt
            print()
            return "EXIT"
        except Exception as e:
            logging.exception(f"Unexpected error in main loop: {e}")
            views.show_error("An unexpected error occurred.")

    session_manager.stop()  # Ensure timer is stopped on normal exit
    return "EXIT"


def start_application():
    """Main application entry point."""
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
        app_session = app.App(profiles_conn, session_god_key)

        while True:
            views.clear_screen()
            views.show_banner()

            all_profiles = database.get_all_profile_names(profiles_conn)
            if all_profiles:
                views.display_profile_list(all_profiles)

            print(
                f"{colors.Colors.BRIGHT_BLUE}Enter a profile name to login or create a new one."
            )
            print(f"Press Enter to exit.{colors.Colors.RESET}\n")

            profile_name = views.prompt_input("Profile name:").lower()

            if not profile_name:
                break

            allowed, wait_time = _rate_limiter.check_attempt(profile_name)
            if not allowed:
                views.show_error(
                    f"Too many failed attempts for '{profile_name}'. Please wait {wait_time} seconds."
                )
                time.sleep(2)
                continue

            profile_details = database.get_profile_details(profiles_conn, profile_name)

            if not profile_details:
                master_password = commands.create_new_profile_flow(profile_name)
                if not master_password:
                    continue

                views.show_loading(f"Creating profile '{profile_name}'")
                if app_session.load_user_profile(profile_name, master_password):
                    _rate_limiter.reset(profile_name)
                else:
                    views.show_error("Failed to create profile.")
                    continue
            else:
                if not commands.login_flow(app_session, profile_name):
                    continue

            action = start_interactive_shell(app_session)
            app_session.unload_profile()

            if action == "EXIT":
                break

    except KeyboardInterrupt:
        print(
            f"\n\n{colors.Colors.BRIGHT_YELLOW}Session interrupted by user.{colors.Colors.RESET}"
        )
    except Exception as e:
        views.show_error(f"A critical error occurred: {e}")
        logging.exception("Critical error in main execution loop.")
    finally:
        if app_session:
            app_session.close_and_save_session()
