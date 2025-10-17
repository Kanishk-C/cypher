"""Command handlers with improved validation and UX."""

import getpass
import random
import string
from core.core import App
from utils.validators import InputValidator
from utils.formatters import UIFormatter
from . import views, colors
from exceptions import *


def add_command(args, app: App):
    """Handles adding a new password entry."""
    views.show_section_header("Add New Password Entry")

    try:
        # Service name
        service = args.service or views.prompt_input("Service name (e.g., 'github', 'gmail'):")
        valid, msg = InputValidator.validate_service_name(service)
        while not valid:
            views.show_warning(msg)
            service = views.prompt_input("Service name:")
            valid, msg = InputValidator.validate_service_name(service)

        # Username
        username = args.username or views.prompt_input(f"Username/email for '{service}':")
        valid, msg = InputValidator.validate_username(username)
        while not valid:
            views.show_warning(msg)
            username = views.prompt_input(f"Username/email for '{service}':")
            valid, msg = InputValidator.validate_username(username)

        # Password
        password = views.prompt_password(f"Password for '{service}':")
        valid, msg = InputValidator.validate_password_strength(password)
        while not valid:
            views.show_warning(msg)
            password = views.prompt_password(f"Password for '{service}':")
            valid, msg = InputValidator.validate_password_strength(password)

        # Confirm password
        password_confirm = views.prompt_password("Confirm password:")
        if password != password_confirm:
            views.show_error("Passwords do not match. Entry not saved.")
            return

        # Optional notes
        notes = views.prompt_input("Notes (optional, press Enter to skip):")
        if notes:
            valid, msg = InputValidator.validate_notes(notes)
            if not valid:
                views.show_warning(msg)
                notes = notes[:1000]

        # Add to database
        views.show_loading("Saving entry")
        app.add_password(service, username, password, notes)
        views.clear_loading()

        views.show_success(f"Password for '{service}' ({username}) added successfully!")

    except DuplicateEntryError:
        views.clear_loading()
        views.show_error(f"Entry already exists for '{service}' with username '{username}'")
        if views.confirm_action("Would you like to update it instead"):
            args.service = service
            args.username = username
            update_command(args, app)
    except CoreException as e:
        views.clear_loading()
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.clear_loading()
        views.show_warning("Add operation cancelled")


def get_command(args, app: App):
    """Handles retrieving and displaying a password."""
    try:
        service_name = args.service
        username = args.username

        if username:
            # Direct retrieval
            views.show_loading(f"Retrieving credentials for '{service_name}'")
            entry = app.get_specific_entry(service_name, username)
            views.clear_loading()
            
            content = {
                "Service": service_name,
                "Username": username,
                "Password": entry['password'],
            }
            if entry.get('notes'):
                content["Notes"] = entry['notes']
            
            print("\n" + UIFormatter.format_box("Credentials Found", content))
            views.wait_for_user()
        else:
            # Check for multiple accounts
            views.show_loading(f"Searching for '{service_name}'")
            all_entries = app.get_entries_by_service(service_name)
            views.clear_loading()

            if len(all_entries) == 1:
                entry = all_entries[0]
                content = {
                    "Service": service_name,
                    "Username": entry['username'],
                    "Password": entry['password'],
                }
                if entry.get('notes'):
                    content["Notes"] = entry['notes']
                
                print("\n" + UIFormatter.format_box("Credentials Found", content))
                views.wait_for_user()
            else:
                # Multiple accounts - show selection menu
                choice = views.show_multiple_accounts_menu(service_name, all_entries)

                if choice.isdigit():
                    choice_num = int(choice)
                    if choice_num == 0:
                        views.show_info("Operation cancelled")
                        return
                    if 0 < choice_num <= len(all_entries):
                        entry = all_entries[choice_num - 1]
                        content = {
                            "Service": service_name,
                            "Username": entry['username'],
                            "Password": entry['password'],
                        }
                        if entry.get('notes'):
                            content["Notes"] = entry['notes']
                        
                        print("\n" + UIFormatter.format_box("Credentials Found", content))
                        views.wait_for_user()
                    else:
                        views.show_error("Invalid selection")
                else:
                    views.show_error("Invalid input. Please enter a number")

    except EntryNotFoundError:
        views.show_error(f"No entries found for '{service_name}'")
        views.show_info("Use 'list' to see all saved services")
    except (DecryptionError, CoreException) as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Operation cancelled")


def list_command(args, app: App):
    """Handles listing all saved services and usernames."""
    try:
        views.show_loading("Loading entries")
        entries = app.list_all_entries()
        views.clear_loading()
        views.display_entry_list(entries)

        if entries:
            views.wait_for_user()
    except CoreException as e:
        views.clear_loading()
        views.show_error(str(e))


def delete_command(args, app: App):
    """Handles deleting a password entry."""
    try:
        service = args.service
        username = args.username

        # Show what will be deleted
        print(f"\n{colors.Colors.BRIGHT_RED}Deleting entry:{colors.Colors.RESET}")
        print(f"  Service:  {colors.Colors.BRIGHT_CYAN}{service}{colors.Colors.RESET}")
        print(f"  Username: {colors.Colors.BRIGHT_CYAN}{username}{colors.Colors.RESET}")

        if args.force or views.confirm_action(
                f"\n{colors.Colors.BRIGHT_RED}Permanently delete this entry{colors.Colors.RESET}"):
            views.show_loading("Deleting entry")
            app.delete_password(service, username)
            views.clear_loading()
            views.show_success(f"Entry for '{service}' ({username}) deleted successfully")
        else:
            views.show_info("Deletion cancelled")

    except EntryNotFoundError:
        views.show_error(f"No entry found for '{service}' with username '{username}'")
        views.show_info("Use 'list' to see all saved entries")
    except CoreException as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Deletion cancelled")


def update_command(args, app: App):
    """Handles updating an existing entry."""
    views.show_section_header("Update Password Entry")

    try:
        service = args.service
        username = args.username

        # Verify entry exists
        views.show_loading(f"Loading entry for '{service}'")
        current_entry = app.get_specific_entry(service, username)
        views.clear_loading()

        print(f"\n{colors.Colors.BRIGHT_BLUE}Current entry:{colors.Colors.RESET}")
        print(f"  Service:  {service}")
        print(f"  Username: {username}")
        print(f"  Password: {colors.Colors.BRIGHT_BLACK}{'*' * len(current_entry['password'])}{colors.Colors.RESET}")
        if current_entry.get('notes'):
            print(f"  Notes:    {current_entry['notes'][:50]}...")

        print(f"\n{colors.Colors.BRIGHT_YELLOW}Enter new values (press Enter to keep current):{colors.Colors.RESET}")

        # Get new password
        new_password = views.prompt_password("New password (or Enter to keep):")
        if new_password:
            valid, msg = InputValidator.validate_password_strength(new_password)
            if not valid:
                views.show_error(msg)
                return
            
            password_confirm = views.prompt_password("Confirm new password:")
            if new_password != password_confirm:
                views.show_error("Passwords do not match. Update cancelled.")
                return
        else:
            new_password = current_entry['password']

        # Get new notes
        new_notes = views.prompt_input("New notes (or Enter to keep):")
        if not new_notes:
            new_notes = current_entry.get('notes', '')
        else:
            valid, msg = InputValidator.validate_notes(new_notes)
            if not valid:
                views.show_warning(msg)
                new_notes = new_notes[:1000]

        # Confirm update
        if views.confirm_action("Save these changes"):
            views.show_loading("Updating entry")
            app.delete_password(service, username)
            app.add_password(service, username, new_password, new_notes)
            views.clear_loading()
            views.show_success(f"Entry for '{service}' ({username}) updated successfully")
        else:
            views.show_info("Update cancelled")

    except EntryNotFoundError:
        views.show_error(f"No entry found for '{service}' with username '{username}'")
    except CoreException as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Update cancelled")


def switch_command(args, app: App):
    """Signal handler for the switch command."""
    pass


def clear_command(args, app: App):
    """Handles clearing the terminal screen."""
    views.clear_screen()
    views.show_banner()
    views.show_profile_header(app.profile_name)
    views.show_quick_help()


def search_command(args, app: App):
    """Search for entries by partial service name."""
    views.show_section_header("Search Entries")

    try:
        search_term = args.query if hasattr(args, 'query') and args.query else views.prompt_input("Search for service:")
        if not search_term:
            views.show_warning("Search term cannot be empty")
            return

        views.show_loading(f"Searching for '{search_term}'")
        all_entries = app.list_all_entries()
        views.clear_loading()

        # Filter entries
        matching_entries = [(s, u) for s, u in all_entries if search_term.lower() in s.lower()]

        if matching_entries:
            print(f"\n{colors.Colors.BRIGHT_GREEN}Found {len(matching_entries)} matching entries:{colors.Colors.RESET}\n")
            views.display_entry_list(matching_entries)
            views.wait_for_user()
        else:
            views.show_warning(f"No entries found matching '{search_term}'")

    except CoreException as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Search cancelled")


def generate_password_command(args, app: App):
    """Generate a secure random password."""
    views.show_section_header("Generate Secure Password")

    try:
        # Get password length
        length_input = views.prompt_input("Password length (default: 16):")
        length = int(length_input) if length_input and length_input.isdigit() else 16

        if length < 8:
            views.show_warning("Password should be at least 8 characters")
            length = 8
        elif length > 128:
            views.show_warning("Password limited to 128 characters")
            length = 128

        # Build character set
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"

        # Generate password
        password = ''.join(random.choice(chars) for _ in range(length))

        # Display generated password
        print(f"\n{colors.Colors.BRIGHT_CYAN}╭{'─' * 60}╮")
        print(f"│ {colors.Colors.BRIGHT_GREEN}Generated Password{colors.Colors.BRIGHT_CYAN}{' ' * 42}│")
        print(f"├{'─' * 60}┤")
        print(f"│ {colors.Colors.BRIGHT_YELLOW}{password}{colors.Colors.BRIGHT_CYAN}{' ' * (59 - len(password))}│")
        print(f"╰{'─' * 60}╯{colors.Colors.RESET}\n")

        # Option to save
        if views.confirm_action("Would you like to save this password"):
            service = views.prompt_input("Service name:")
            username = views.prompt_input("Username/email:")
            notes = views.prompt_input("Notes (optional):")

            if service and username:
                app.add_password(service, username, password, notes)
                views.show_success(f"Password saved for '{service}'")
            else:
                views.show_warning("Service and username required. Password not saved.")

    except ValueError:
        views.show_error("Invalid input")
    except CoreException as e:
        views.show_error(str(e))
    except KeyboardInterrupt:
        views.show_warning("Password generation cancelled")