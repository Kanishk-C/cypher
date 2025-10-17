"""Handles all user-facing output and display formatting."""

import os
import platform
import shutil
from . import colors


def get_terminal_width():
    """Get the current terminal width, with fallback."""
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80


def show_banner():
    """Displays application banner."""
    width = get_terminal_width()

    banner_lines = [
        "   ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗ ",
        "  ██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗",
        "  ██║      ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝",
        "  ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗",
        "  ╚██████╗   ██║   ██║     ██║  ██║███████╗██║  ██║",
        "   ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
    ]

    subtitle = "Secure Local Password Manager"
    tagline = "Your secrets, your device, your control"

    print()
    for i, line in enumerate(banner_lines):
        if i < 2:
            color = colors.Colors.BRIGHT_CYAN
        elif i < 4:
            color = colors.Colors.BRIGHT_BLUE
        else:
            color = colors.Colors.BRIGHT_BLUE

        padding = max(0, (width - len(line)) // 2)
        print(f"{' ' * padding}{color}{line}{colors.Colors.RESET}")

    print()
    subtitle_len = len(subtitle)
    line_length = max(0, (width - subtitle_len - 4) // 2)

    if line_length > 5:
        left_line = '─' * line_length
        right_line = '─' * (width - line_length - subtitle_len - 4)
        print(f"{colors.Colors.BRIGHT_CYAN}{left_line} {colors.Colors.BRIGHT_GREEN}{subtitle}{colors.Colors.BRIGHT_CYAN} {right_line}{colors.Colors.RESET}")
    else:
        subtitle_padding = max(0, (width - subtitle_len) // 2)
        print(f"{' ' * subtitle_padding}{colors.Colors.BRIGHT_GREEN}{subtitle}{colors.Colors.RESET}")

    tagline_padding = max(0, (width - len(tagline)) // 2)
    print(f"{' ' * tagline_padding}{colors.Colors.GRAY}{tagline}{colors.Colors.RESET}")
    print()


def show_profile_header(profile_name):
    """Shows a compact profile indicator."""
    print(f"\n{colors.Colors.BRIGHT_CYAN}┌─ Profile: {colors.Colors.BRIGHT_GREEN}{profile_name}{colors.Colors.BRIGHT_CYAN} ─┐{colors.Colors.RESET}")


def show_section_header(title):
    """Shows a section header."""
    width = min(get_terminal_width(), 80)
    line = "─" * (width - 4)
    print(f"\n{colors.Colors.BRIGHT_BLUE}┌─ {title}")
    print(f"└{line}{colors.Colors.RESET}")


def show_quick_help():
    """Displays quick access commands."""
    commands = [
        ("add", "Add new password", "a"),
        ("get", "Retrieve password", "g"),
        ("list", "List all entries", "l"),
        ("delete", "Delete entry", "d"),
        ("update", "Update password", "u"),
        ("search", "Search entries", "s"),
        ("generate", "Generate password", "gen"),
        ("clear", "Clear screen", "cls"),
        ("help", "Show full help", "h"),
        ("restart", "Switch profile", ""),
        ("exit", "Quit application", "q")
    ]

    print(f"{colors.Colors.BRIGHT_YELLOW}┌─ Quick Commands{colors.Colors.RESET}")
    print(f"{colors.Colors.BRIGHT_YELLOW}│{colors.Colors.RESET}")

    for cmd, desc, alias in commands:
        if alias:
            cmd_display = f"{cmd}/{alias}"
        else:
            cmd_display = cmd
        print(f"{colors.Colors.BRIGHT_YELLOW}│{colors.Colors.RESET}  {colors.Colors.BRIGHT_CYAN}{cmd_display:<17}{colors.Colors.RESET} {desc}")

    print(f"{colors.Colors.BRIGHT_YELLOW}└{'─' * 50}{colors.Colors.RESET}\n")


def clear_screen():
    """Clears the terminal screen."""
    os.system("cls" if platform.system() == "Windows" else "clear")


def wait_for_user():
    """Pauses and waits for user to press Enter."""
    print(f"\n{colors.Colors.BRIGHT_YELLOW}Press Enter to continue...{colors.Colors.RESET}", end="")
    try:
        input()
    except KeyboardInterrupt:
        print()


def display_entry_list(entries):
    """Displays an improved list of all entries."""
    show_section_header("Saved Credentials")

    if not entries:
        print(f"{colors.Colors.BRIGHT_YELLOW}  No entries found in the vault.{colors.Colors.RESET}\n")
        return

    # Group by service
    services = {}
    for service, username in entries:
        if service not in services:
            services[service] = []
        services[service].append(username)

    count = 0
    for service in sorted(services.keys()):
        usernames = services[service]
        count += len(usernames)

        account_info = f"({len(usernames)} account{'s' if len(usernames) > 1 else ''})"
        print(f"\n  {colors.Colors.BRIGHT_CYAN}●{colors.Colors.RESET} {colors.Colors.BRIGHT_GREEN}{service}{colors.Colors.RESET} {colors.Colors.BRIGHT_BLACK}{account_info}{colors.Colors.RESET}")

        for username in usernames:
            print(f"    {colors.Colors.BRIGHT_BLACK}└─{colors.Colors.RESET} {username}")

    print(f"\n{colors.Colors.BRIGHT_BLACK}Total: {count} credential{'s' if count != 1 else ''}{colors.Colors.RESET}\n")


def show_success(message):
    """Display a success message."""
    print(f"\n{colors.Colors.BRIGHT_GREEN}✓ {message}{colors.Colors.RESET}")


def show_error(message):
    """Display an error message."""
    print(f"\n{colors.Colors.BRIGHT_RED}✗ {message}{colors.Colors.RESET}")


def show_warning(message):
    """Display a warning message."""
    print(f"\n{colors.Colors.BRIGHT_YELLOW}⚠ {message}{colors.Colors.RESET}")


def show_info(message):
    """Display an info message."""
    print(f"\n{colors.Colors.BRIGHT_BLUE}ℹ {message}{colors.Colors.RESET}")


def prompt_input(prompt_text, color=colors.Colors.BRIGHT_BLUE):
    """Standardized input prompt."""
    return input(f"{color}❯ {prompt_text}{colors.Colors.RESET} ").strip()


def prompt_password(prompt_text):
    """Standardized password prompt."""
    import getpass
    return getpass.getpass(f"{colors.Colors.BRIGHT_BLUE}❯ {prompt_text} {colors.Colors.RESET}")


def show_multiple_accounts_menu(service_name, entries):
    """Display a selection menu for multiple accounts."""
    show_section_header(f"Multiple Accounts for '{service_name}'")

    for i, entry in enumerate(entries, 1):
        print(f"  {colors.Colors.BRIGHT_CYAN}{i}.{colors.Colors.RESET} {entry['username']}")

    print(f"\n  {colors.Colors.BRIGHT_CYAN}0.{colors.Colors.RESET} Cancel")

    return prompt_input("\nSelect an account:")


def confirm_action(action_description):
    """Prompt for confirmation."""
    response = prompt_input(f"{action_description}? (y/N)", colors.Colors.BRIGHT_YELLOW).lower()
    return response == 'y'


def show_loading(message="Processing"):
    """Show a loading message."""
    print(f"{colors.Colors.BRIGHT_BLUE}⟳ {message}...{colors.Colors.RESET}", end="", flush=True)


def clear_loading():
    """Clear the loading message."""
    print("\r" + " " * 50 + "\r", end="", flush=True)


def suggest_command(user_input, available_commands):
    """Suggests similar commands if user makes a typo."""
    from difflib import get_close_matches

    matches = get_close_matches(user_input, available_commands, n=3, cutoff=0.6)
    if matches:
        print(f"\n{colors.Colors.BRIGHT_YELLOW}Did you mean:{colors.Colors.RESET}")
        for match in matches:
            print(f"  {colors.Colors.BRIGHT_CYAN}→ {match}{colors.Colors.RESET}")
    else:
        print(f"\n{colors.Colors.BRIGHT_YELLOW}Type '{colors.Colors.BRIGHT_CYAN}help{colors.Colors.BRIGHT_YELLOW}' to see available commands{colors.Colors.RESET}")


def show_stats(total_entries, total_services):
    """Shows vault statistics."""
    print(f"\n{colors.Colors.BRIGHT_CYAN}┌─ Vault Statistics")
    print(f"│  Total Entries:  {colors.Colors.BRIGHT_GREEN}{total_entries}{colors.Colors.RESET}")
    print(f"{colors.Colors.BRIGHT_CYAN}│  Total Services: {colors.Colors.BRIGHT_GREEN}{total_services}{colors.Colors.RESET}")
    print(f"{colors.Colors.BRIGHT_CYAN}└{'─' * 30}{colors.Colors.RESET}\n")


def show_recent_activity(entries, limit=5):
    """Shows recently accessed entries."""
    if not entries:
        return

    print(f"\n{colors.Colors.BRIGHT_CYAN}┌─ Recent Entries{colors.Colors.RESET}")
    for service, username in entries[:limit]:
        print(f"{colors.Colors.BRIGHT_CYAN}│{colors.Colors.RESET}  {colors.Colors.BRIGHT_GREEN}●{colors.Colors.RESET} {service} ({username})")
    print(f"{colors.Colors.BRIGHT_CYAN}└{'─' * 30}{colors.Colors.RESET}\n")