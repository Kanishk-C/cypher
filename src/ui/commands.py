"""Command handlers with improved validation and UX - v1.0.0 PRODUCTION READY."""

import secrets
import string
import shutil
import os
from datetime import datetime
from typing import Optional

from src.data import database
from src.core import app
from src.core.crypto import safe_string_compare
from src.core.secure_string import SecureString
from src.utils.validators import InputValidator
from src.ui import views, colors
from src.exceptions import (
    CoreException,
    DuplicateEntryError,
    EntryNotFoundError,
    DecryptionError,
)
from src.config import Config


# ============================================
# COMMAND HANDLERS
# ============================================


def add_command(args, app_session: app.App):
    """
    Add a new password entry to the vault.

    Prompts for:
    - Service name
    - Username/email
    - Password (with confirmation)
    - Optional notes

    Args:
        args: Command line arguments
        app_session: Active application session
    """
    views.show_section_header("Add New Password Entry")

    try:
        # Get service name
        service = args.service or views.prompt_input("Service name:")
        valid, msg = InputValidator.validate_service_name(service)
        if not valid:
            views.show_warning(msg)
            return

        # Get username
        username = args.username or views.prompt_input(f"Username for '{service}':")
        valid, msg = InputValidator.validate_username(username)
        if not valid:
            views.show_warning(msg)
            return

        # Get password with confirmation
        password_str = views.prompt_password_masked(f"Password for '{service}':")

        # Offer to generate password if empty
        if not password_str:
            if views.confirm_action("Generate a secure password?"):
                password_str = generate_secure_password(length=16)
                views.show_info(f"Generated password: {password_str}")
                if not views.confirm_action("Use this password?"):
                    views.show_warning("Add operation cancelled.")
                    return
            else:
                views.show_warning("Password cannot be empty.")
                return

        confirm_str = views.prompt_password_masked("Confirm password:")

        with SecureString(password_str) as s_pass, SecureString(
            confirm_str
        ) as s_confirm:
            if not safe_string_compare(s_pass.get(), s_confirm.get()):
                views.show_error("Passwords do not match.")
                return

        # Get optional notes
        notes = views.prompt_input("Notes (optional):")
        valid, msg = InputValidator.validate_notes(notes)
        if not valid:
            views.show_warning(msg)
            return

        # Save to vault
        app_session.add_password(service, username, password_str, notes)
        views.show_success(f"Entry for '{service}' saved successfully!")

    except DuplicateEntryError as e:
        views.show_error(str(e))
    except CoreException as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Add operation cancelled.")


def get_command(args, app_session: app.App):
    """
    Retrieve and display a password entry.

    If username not provided and multiple accounts exist for the service,
    prompts user to select which account.

    Args:
        args: Command line arguments (service, optional username)
        app_session: Active application session
    """
    try:
        service_name = args.service
        username = args.username

        if username:
            # Specific username provided
            entry = app_session.get_specific_entry(service_name, username)
            views.display_entry_details(
                service_name, username, entry["password"], entry.get("notes")
            )
        else:
            # No username - get all for service
            all_entries = app_session.get_entries_by_service(service_name)

            if len(all_entries) == 1:
                # Only one account, display it
                entry = all_entries[0]
                views.display_entry_details(
                    service_name,
                    entry["username"],
                    entry["password"],
                    entry.get("notes"),
                )
            else:
                # Multiple accounts, let user choose
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
    """
    List all saved services and usernames.

    Args:
        args: Command line arguments
        app_session: Active application session
    """
    try:
        entries = app_session.list_all_entries()

        if entries:
            # Show count in header
            total_entries = len(entries)
            total_services = len(set(service for service, _ in entries))

            views.display_entry_list(entries)
            print(
                f"\n{colors.Colors.MUTED}Total: {total_entries} entries across "
                f"{total_services} services{colors.Colors.RESET}\n"
            )
        else:
            views.show_info("No entries found. Use 'add' to create your first entry.")

    except CoreException as e:
        views.show_error(str(e))


def delete_command(args, app_session: app.App):
    """
    Delete a password entry.

    Args:
        args: Command line arguments (service, username, optional --force)
        app_session: Active application session
    """
    try:
        service = args.service
        username = args.username

        if args.force or views.confirm_action(
            f"⚠ Permanently delete entry for '{service}' ({username})?"
        ):
            app_session.delete_password(service, username)
            views.show_success("Entry deleted successfully.")
        else:
            views.show_info("Deletion cancelled.")

    except EntryNotFoundError as e:
        views.show_error(str(e))
    except CoreException as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Deletion cancelled.")


def update_command(args, app_session: app.App):
    """
    Update an existing password entry.

    Allows updating password and/or notes.
    Press Enter to keep current values.

    Args:
        args: Command line arguments (service, username)
        app_session: Active application session
    """
    views.show_section_header("Update Password Entry")

    try:
        service = args.service
        username = args.username

        # Get current entry
        current_entry = app_session.get_specific_entry(service, username)

        views.show_info(
            f"Updating entry for {service} ({username}). Press Enter to keep current values."
        )

        # Get new password (optional)
        new_password = views.prompt_password_masked("New password (or Enter to keep):")

        if new_password:
            # Confirm new password
            password_confirm = views.prompt_password_masked("Confirm new password:")
            if not safe_string_compare(new_password, password_confirm):
                views.show_error("Passwords do not match. Update cancelled.")
                return
        else:
            # Keep current password
            new_password = current_entry["password"]

        # Get new notes (optional)
        new_notes = views.prompt_input(
            "New notes (or Enter to keep):"
        ) or current_entry.get("notes", "")

        # Confirm update
        if not views.confirm_action("⚠ Save these changes? This cannot be undone."):
            views.show_info("Update cancelled.")
            return

        # Update entry (delete + add)
        app_session.delete_password(service, username)
        app_session.add_password(service, username, new_password, new_notes)
        views.show_success(f"Entry for '{service}' updated successfully!")

    except EntryNotFoundError as e:
        views.show_error(str(e))
    except CoreException as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Update cancelled.")


def search_command(args, app_session: app.App):
    """
    Search for entries by partial service name (case-insensitive).

    Args:
        args: Command line arguments (optional query)
        app_session: Active application session
    """
    try:
        search_term = args.query or views.prompt_input("Search for service:")

        if not search_term:
            return

        # Get all entries and filter
        all_entries = app_session.list_all_entries()
        matching_entries = [
            (s, u) for s, u in all_entries if search_term.lower() in s.lower()
        ]

        if matching_entries:
            views.display_entry_list(matching_entries, search_term)
            print(
                f"\n{colors.Colors.MUTED}Found {len(matching_entries)} "
                f"matching entries{colors.Colors.RESET}\n"
            )
        else:
            views.show_warning(f"No entries found matching '{search_term}'.")

    except CoreException as e:
        views.show_error(str(e))


def generate_secure_password(
    length: int = 16,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Password length (8-128)
        use_lowercase: Include lowercase letters
        use_uppercase: Include uppercase letters
        use_digits: Include digits
        use_symbols: Include symbols

    Returns:
        Generated password string
    """
    # Clamp length
    length = max(8, min(128, length))

    char_pool = ""
    password_chars = []

    # Build character pool and ensure at least one of each type
    if use_lowercase:
        char_pool += string.ascii_lowercase
        password_chars.append(secrets.choice(string.ascii_lowercase))

    if use_uppercase:
        char_pool += string.ascii_uppercase
        password_chars.append(secrets.choice(string.ascii_uppercase))

    if use_digits:
        char_pool += string.digits
        password_chars.append(secrets.choice(string.digits))

    if use_symbols:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        char_pool += symbols
        password_chars.append(secrets.choice(symbols))

    # Fill remaining length with random characters from pool
    remaining_length = length - len(password_chars)
    password_chars.extend(secrets.choice(char_pool) for _ in range(remaining_length))

    # Shuffle to randomize position of guaranteed characters
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


def generate_password_command(args, app_session: app.App):
    """
    Generate a secure random password interactively.

    Prompts user for:
    - Length
    - Character sets to include
    - Option to save to vault

    Args:
        args: Command line arguments
        app_session: Active application session
    """
    views.show_section_header("Generate Secure Password")

    try:
        # Get desired length
        length_input = views.prompt_input("Password length (default: 16):")
        length = int(length_input) if length_input.isdigit() else 16

        if length < 8:
            views.show_warning("Minimum length is 8 characters.")
            length = 8
        if length > 128:
            views.show_warning("Maximum length is 128 characters.")
            length = 128

        # Ask about character sets
        use_lowercase = views.confirm_action("Include lowercase? (abc)")
        use_uppercase = views.confirm_action("Include uppercase? (ABC)")
        use_digits = views.confirm_action("Include numbers? (123)")
        use_symbols = views.confirm_action("Include symbols? (!@#)")

        # Validate at least one character set selected
        if not any([use_lowercase, use_uppercase, use_digits, use_symbols]):
            views.show_error(
                "Cannot generate a password with no character sets selected."
            )
            return

        # Generate password
        password = generate_secure_password(
            length=length,
            use_lowercase=use_lowercase,
            use_uppercase=use_uppercase,
            use_digits=use_digits,
            use_symbols=use_symbols,
        )

        # Display generated password
        views.display_generated_password(password)

        # Offer to save to vault
        if views.confirm_action("Save this password to a new entry?"):
            service = views.prompt_input("Service name:")
            username = views.prompt_input("Username/email:")

            if service and username:
                # Validate inputs
                valid, msg = InputValidator.validate_service_name(service)
                if not valid:
                    views.show_warning(f"{msg} Password not saved.")
                    return

                valid, msg = InputValidator.validate_username(username)
                if not valid:
                    views.show_warning(f"{msg} Password not saved.")
                    return

                # Save to vault
                app_session.add_password(service, username, password, "")
                views.show_success(f"Password saved for '{service}'.")
            else:
                views.show_warning(
                    "Service and username are required. Password not saved."
                )

    except (ValueError, CoreException) as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Generation cancelled.")


def export_profile_command(args, app_session: app.App):
    """
    Export encrypted profile backup to file.

    Creates a timestamped backup of the current profile's encrypted database.
    The backup remains encrypted and can be restored later.

    Args:
        args: Command line arguments (optional export_path)
        app_session: Active application session
    """
    if not app_session.is_profile_loaded():
        views.show_error("No profile loaded.")
        return

    views.show_section_header("Export Profile Backup")

    try:
        # Get export path
        if hasattr(args, "export_path") and args.export_path:
            export_path = args.export_path
        else:
            default_name = (
                f"{app_session.profile_name}_backup_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.cypher"
            )
            export_input = views.prompt_input(f"Export path (default: {default_name}):")
            export_path = export_input.strip() or default_name

        # Ensure profile is saved
        print(
            f"{colors.Colors.INFO}⟳ Saving profile...{colors.Colors.RESET}",
            end="",
            flush=True,
        )
        app_session.save_profile()
        print("\r" + " " * 50 + "\r", end="", flush=True)

        # Copy encrypted profile file
        source = database.get_user_profile_path(app_session.profile_name)

        if not os.path.exists(source):
            views.show_error("Profile file not found. Cannot export.")
            return

        # Create backup
        print(
            f"{colors.Colors.INFO}⟳ Creating backup...{colors.Colors.RESET}",
            end="",
            flush=True,
        )
        shutil.copy2(source, export_path)
        print("\r" + " " * 50 + "\r", end="", flush=True)

        # Verify backup
        if os.path.exists(export_path):
            file_size = os.path.getsize(export_path)
            views.show_success(
                f"Profile exported successfully!\n"
                f"  Location: {os.path.abspath(export_path)}\n"
                f"  Size: {file_size:,} bytes"
            )
            print(
                f"\n{colors.Colors.WARNING}⚠ Keep this backup file secure. "
                f"It is encrypted but contains your vault.{colors.Colors.RESET}\n"
            )
        else:
            views.show_error("Export verification failed.")

    except Exception as e:
        print("\r" + " " * 50 + "\r", end="", flush=True)
        views.show_error(f"Export failed: {e}")


def switch_command(args, app_session: app.App):
    """
    Switch to another profile (handled by CLI).

    Args:
        args: Command line arguments
        app_session: Active application session
    """
    pass  # Actual switching handled in CLI


def clear_command(args, app_session: app.App):
    """
    Clear the terminal screen and redisplay header.

    Args:
        args: Command line arguments
        app_session: Active application session
    """
    views.clear_screen()
    views.show_banner()
    if app_session.profile_name:
        # Get entry count for header
        try:
            entries = app_session.list_all_entries()
            entry_count = len(entries)
        except:
            entry_count = None
        views.show_profile_header(app_session.profile_name, entry_count)


def delete_profile_command(args, app_session: app.App):
    """
    Permanently delete a profile and all its data.

    This action is irreversible. Cannot delete currently loaded profile.

    Args:
        args: Command line arguments (profile_name)
        app_session: Active application session
    """
    profile_name = args.profile_name.lower()

    # Check profile exists
    all_profiles = database.get_all_profile_names(app_session.profiles_conn)
    if profile_name not in all_profiles:
        views.show_error(f"Profile '{profile_name}' does not exist.")
        return

    # Prevent deleting currently loaded profile
    if app_session.profile_name == profile_name:
        views.show_error(
            "Cannot delete the currently loaded profile. "
            "Switch to another profile first."
        )
        return

    # Confirm deletion
    views.show_warning(
        f"You are about to permanently delete the profile '{profile_name}' "
        f"and all its data."
    )

    if not views.confirm_action("⚠ This action is irreversible. Are you sure?"):
        views.show_info("Deletion cancelled.")
        return

    # Double confirmation
    confirm_text = views.prompt_input(
        f"Type the profile name '{profile_name}' to confirm:"
    )

    if confirm_text.lower() != profile_name:
        views.show_error("Profile name did not match. Deletion cancelled.")
        return

    try:
        app_session.delete_profile(profile_name)
        views.show_success(f"Profile '{profile_name}' has been securely deleted.")
    except CoreException as e:
        views.show_error(str(e))


# ============================================
# HELPER FLOWS
# ============================================


def create_new_profile_flow(profile_name: str) -> Optional[str]:
    """
    Guide user through creating a new profile and master password.

    Validates password strength and confirms password entry.

    Args:
        profile_name: Name of profile to create

    Returns:
        Master password string, or None if cancelled
    """
    views.show_section_header(f"Create New Profile: {profile_name}")

    while True:
        p1_str = views.prompt_password_masked(
            f"Create master password (min {Config.MIN_MASTER_PASSWORD_LENGTH} chars): "
        )

        # Validate password strength
        valid, msg = InputValidator.validate_password_strength(
            p1_str, Config.MIN_MASTER_PASSWORD_LENGTH
        )
        if not valid:
            views.show_warning(msg)
            continue

        # Confirm password
        p2_str = views.prompt_password_masked("Confirm master password: ")

        if safe_string_compare(p1_str, p2_str):
            return p1_str
        else:
            views.show_error("Passwords do not match.")
            if not views.confirm_action("Try again?"):
                return None


def login_flow(app_session: app.App, profile_name: str) -> bool:
    """
    Handle login process for existing profile.

    Allows up to 3 attempts before failing.

    Args:
        app_session: Application session
        profile_name: Profile name to log into

    Returns:
        True if login successful, False otherwise
    """
    max_attempts = Config.MAX_LOGIN_ATTEMPTS

    for attempt in range(max_attempts):
        master_password_str = views.prompt_password_masked(
            f"Master password for '{profile_name}': "
        )

        if app_session.load_user_profile(profile_name, master_password_str):
            return True
        else:
            remaining = max_attempts - attempt - 1

            if remaining > 0:
                # Show error with remaining attempts
                print(
                    f"\n{colors.Colors.ERROR}✗ Incorrect password. "
                    f"{colors.Colors.WARNING}{remaining} attempt{'s' if remaining != 1 else ''} remaining."
                    f"{colors.Colors.RESET}"
                )
            else:
                # Final failure
                print(
                    f"\n{colors.Colors.CRITICAL}✗ Authentication failed. "
                    f"Too many incorrect attempts.{colors.Colors.RESET}"
                )
                return False

    return False
