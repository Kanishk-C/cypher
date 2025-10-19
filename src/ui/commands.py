"""Command handlers with improved validation and UX."""

import getpass
import random
import string
from src.core import app
from src.utils.validators import InputValidator
from src.utils.formatters import UIFormatter
from src.ui import views, colors
from src.exceptions import (
    CoreException,
    DuplicateEntryError,
    EntryNotFoundError,
    DecryptionError,
)
from src.config import Config

# --- Command Handlers ---


def add_command(args, app_session: app.App):
    """Handles adding a new password entry."""
    views.show_section_header("Add New Password Entry")
    try:
        service = args.service or views.prompt_input("Service name:")
        valid, msg = InputValidator.validate_service_name(service)
        if not valid:
            views.show_warning(msg)
            return

        username = args.username or views.prompt_input(f"Username for '{service}':")
        valid, msg = InputValidator.validate_username(username)
        if not valid:
            views.show_warning(msg)
            return

        password = views.prompt_password_masked(f"Password for '{service}':")
        password_confirm = views.prompt_password_masked("Confirm password:")
        if password != password_confirm:
            views.show_error("Passwords do not match.")
            return

        notes = views.prompt_input("Notes (optional):")

        app_session.add_password(service, username, password, notes)
        views.show_success(f"Entry for '{service}' saved successfully!")

    except DuplicateEntryError as e:
        views.show_error(str(e))
    except CoreException as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Add operation cancelled.")


def get_command(args, app_session: app.App):
    """Handles retrieving and displaying a password."""
    try:
        service_name = args.service
        username = args.username

        if username:
            entry = app_session.get_specific_entry(service_name, username)
            views.display_entry_details(
                service_name, username, entry["password"], entry.get("notes")
            )
        else:
            all_entries = app_session.get_entries_by_service(service_name)
            if len(all_entries) == 1:
                entry = all_entries[0]
                views.display_entry_details(
                    service_name,
                    entry["username"],
                    entry["password"],
                    entry.get("notes"),
                )
            else:
                choice = views.show_multiple_accounts_menu(service_name, all_entries)
                if choice.isdigit() and 0 < int(choice) <= len(all_entries):
                    entry = all_entries[int(choice) - 1]
                    views.display_entry_details(
                        service_name,
                        entry["username"],
                        entry["password"],
                        entry.get("notes"),
                    )

    except EntryNotFoundError as e:
        views.show_error(str(e))
    except (DecryptionError, CoreException) as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Operation cancelled.")


def list_command(args, app_session: app.App):
    """Handles listing all saved services and usernames."""
    try:
        entries = app_session.list_all_entries()
        views.display_entry_list(entries)
    except CoreException as e:
        views.show_error(str(e))


def delete_command(args, app_session: app.App):
    """Handles deleting a password entry."""
    try:
        service = args.service
        username = args.username
        if args.force or views.confirm_action(
            f"Permanently delete entry for '{service}' ({username})?"
        ):
            app_session.delete_password(service, username)
            views.show_success("Entry deleted successfully.")
    except EntryNotFoundError as e:
        views.show_error(str(e))
    except CoreException as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Deletion cancelled.")


def update_command(args, app_session: app.App):
    """Handles updating an existing entry."""
    views.show_section_header("Update Password Entry")
    try:
        service = args.service
        username = args.username

        # Verify entry exists
        views.show_loading(f"Loading entry for '{service}'")
        current_entry = app_session.get_specific_entry(service, username)
        views.clear_loading()

        print(
            f"\n{colors.Colors.BRIGHT_YELLOW}Enter new values (press Enter to keep current):{colors.Colors.RESET}"
        )

        # Get new password
        new_password = views.prompt_password_masked("New password (or Enter to keep):")
        if new_password:
            valid, msg = InputValidator.validate_password_strength(new_password)
            if not valid:
                views.show_error(msg)
                return

            password_confirm = views.prompt_password_masked("Confirm new password:")
            if new_password != password_confirm:
                views.show_error("Passwords do not match. Update cancelled.")
                return
        else:
            new_password = current_entry["password"]

        # Get new notes
        new_notes = views.prompt_input("New notes (or Enter to keep):")
        if not new_notes:
            new_notes = current_entry.get("notes", "")

        # Confirm update
        if views.confirm_action("Save these changes?"):
            views.show_loading("Updating entry")
            app_session.delete_password(service, username)
            app_session.add_password(service, username, new_password, new_notes)
            views.clear_loading()
            views.show_success(f"Entry for '{service}' updated successfully!")
        else:
            views.show_info("Update cancelled.")

    except EntryNotFoundError as e:
        views.show_error(str(e))
    except CoreException as e:
        views.show_error(str(e))


def search_command(args, app_session: app.App):
    """Search for entries by partial service name."""
    try:
        search_term = args.query or views.prompt_input("Search for service:")
        if not search_term:
            return

        all_entries = app_session.list_all_entries()
        matching_entries = [
            (s, u) for s, u in all_entries if search_term.lower() in s.lower()
        ]

        if matching_entries:
            views.display_entry_list(matching_entries, search_term)
        else:
            views.show_warning(f"No entries found matching '{search_term}'.")

    except CoreException as e:
        views.show_error(str(e))


def generate_password_command(args, app_session: app.App):
    """Generate a secure random password."""
    views.show_section_header("Generate Secure Password")
    try:
        length_input = views.prompt_input("Password length (default: 16):")
        length = int(length_input) if length_input.isdigit() else 16

        char_pool = ""
        password_chars = []

        if views.confirm_action("Include lowercase letters (abc)?"):
            char_pool += string.ascii_lowercase
            password_chars.append(random.choice(string.ascii_lowercase))
        if views.confirm_action("Include uppercase letters (ABC)?"):
            char_pool += string.ascii_uppercase
            password_chars.append(random.choice(string.ascii_uppercase))
        if views.confirm_action("Include numbers (123)?"):
            char_pool += string.digits
            password_chars.append(random.choice(string.digits))
        if views.confirm_action("Include symbols (!@#)?"):
            symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            char_pool += symbols
            password_chars.append(random.choice(symbols))

        if not char_pool:
            views.show_error("Cannot generate a password with no character sets.")
            return

        remaining_length = length - len(password_chars)
        if remaining_length > 0:
            password_chars.extend(
                random.choice(char_pool) for _ in range(remaining_length)
            )

        random.shuffle(password_chars)
        password = "".join(password_chars)

        views.display_generated_password(password)

        if views.confirm_action("Save this password to a new entry?"):
            service = views.prompt_input("Service name:")
            username = views.prompt_input("Username/email:")
            if service and username:
                app_session.add_password(service, username, password, "")
                views.show_success(f"Password saved for '{service}'.")
            else:
                views.show_warning(
                    "Service and username are required. Password not saved."
                )

    except (ValueError, CoreException) as e:
        views.show_error(str(e))


def switch_command(args, app_session: app.App):
    """Signal handler for the switch command."""
    pass  # Handled in the CLI loop


# --- Helper Flows for CLI ---


def create_new_profile_flow(profile_name: str) -> str | None:
    """Guides user through creating a new profile and master password."""
    views.show_section_header(f"Create New Profile: {profile_name}")
    while True:
        p1 = views.prompt_password_masked(
            f"Create master password (min {Config.MIN_MASTER_PASSWORD_LENGTH} chars):"
        )
        valid, msg = InputValidator.validate_password_strength(
            p1, Config.MIN_MASTER_PASSWORD_LENGTH
        )
        if not valid:
            views.show_warning(msg)
            continue

        p2 = views.prompt_password_masked("Confirm master password:")
        if p1 == p2:
            return p1
        else:
            views.show_error("Passwords do not match.")
            if not views.confirm_action("Try again?"):
                return None


def login_flow(app_session: app.App, profile_name: str) -> bool:
    """Handles the login process for an existing profile."""
    max_attempts = 3
    for attempt in range(max_attempts):
        master_password = views.prompt_password_masked(
            f"Master password for '{profile_name}':"
        )
        if app_session.load_user_profile(profile_name, master_password):
            return True
        else:
            remaining = max_attempts - attempt - 1
            if remaining > 0:
                views.show_error(f"Incorrect password. {remaining} attempts remaining.")
            else:
                views.show_error("Too many failed attempts.")
                return False
    return False


def clear_command(args, app_session: app.App):
    """Handles clearing the terminal screen."""
    views.clear_screen()
    views.show_banner()
    if app_session.profile_name:
        views.show_profile_header(app_session.profile_name)
