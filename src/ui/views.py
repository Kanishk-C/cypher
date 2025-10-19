"""Handles all user-facing output and display formatting."""

import os
import platform
import shutil
import re
from src.ui import colors
from src.config import Config


def get_terminal_width():
    """Get the current terminal width."""
    try:
        return min(shutil.get_terminal_size().columns, Config.TERMINAL_MAX_WIDTH)
    except:
        return 80


def show_banner():
    """Displays application banner."""
    banner = [
        "   ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗ ",
        "  ██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗",
        "  ██║      ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝",
        "  ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗",
        "  ╚██████╗   ██║   ██║     ██║  ██║███████╗██║  ██║",
        "   ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
    ]
    # Iterate with index to apply different colors
    for i, line in enumerate(banner):
        if i < 3:
            color = colors.Colors.BRIGHT_CYAN
        else:
            color = colors.Colors.BRIGHT_BLUE

        print(f"{color}{line.center(get_terminal_width())}{colors.Colors.RESET}")
    print()


def show_profile_header(profile_name):
    print(
        f"\n{colors.Colors.BRIGHT_CYAN}┌─ Profile: {colors.Colors.BRIGHT_GREEN}{profile_name}{colors.Colors.BRIGHT_CYAN} ─┐{colors.Colors.RESET}"
    )


def show_section_header(title):
    print(f"\n{colors.Colors.BRIGHT_BLUE}─── {title} ───{colors.Colors.RESET}")


def show_quick_help():
    """Displays quick access commands."""
    commands = {
        "add/a": "Add new password",
        "get/g": "Retrieve password",
        "list/ls": "List all entries",
        "delete/rm": "Delete an entry",
        "update/u": "Update an entry",
        "search/s": "Search entries",
        "generate/gen": "Generate password",
        "clear/c": "Clear the screen",
        "switch": "Switch profile",
        "exit/q": "Quit application",
    }
    print(f"\n{colors.Colors.BRIGHT_YELLOW}Quick Commands:{colors.Colors.RESET}")
    for cmd, desc in commands.items():
        print(f"  {colors.Colors.BRIGHT_CYAN}{cmd:<15}{colors.Colors.RESET}{desc}")
    print()


def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")


def confirm_action(prompt: str) -> bool:
    response = input(
        f"{colors.Colors.BRIGHT_YELLOW}❯ {prompt} (y/N):{colors.Colors.RESET} "
    ).lower()
    return response == "y"


def display_profile_list(profiles):
    print(
        f"{colors.Colors.BRIGHT_CYAN}Available Profiles: {colors.Colors.BRIGHT_GREEN}{', '.join(profiles)}{colors.Colors.RESET}\n"
    )


def display_entry_list(entries, search_term: str = ""):
    show_section_header("Saved Credentials")
    if not entries:
        print(f"{colors.Colors.BRIGHT_YELLOW}  No entries found.{colors.Colors.RESET}")
        return

    for service, username in entries:
        display_service = service
        if search_term:
            display_service = re.sub(
                f"({re.escape(search_term)})",
                f"{colors.Colors.BRIGHT_YELLOW}\\1{colors.Colors.RESET}",
                service,
                flags=re.IGNORECASE,
            )
        print(
            f"  {colors.Colors.BRIGHT_CYAN}● {colors.Colors.RESET}{display_service} "
            f"({colors.Colors.BRIGHT_GREEN}{username}{colors.Colors.RESET})"
        )


def display_entry_details(service, username, password, notes):
    print(
        "\n"
        + f"  {colors.Colors.BRIGHT_CYAN}Service:  {colors.Colors.RESET}{service}"
        + "\n"
        + f"  {colors.Colors.BRIGHT_CYAN}Username: {colors.Colors.RESET}{username}"
        + "\n"
        + f"  {colors.Colors.BRIGHT_CYAN}Password: {colors.Colors.BRIGHT_GREEN}{password}{colors.Colors.RESET}"
        + (
            f"\n  {colors.Colors.BRIGHT_CYAN}Notes:    {colors.Colors.RESET}{notes}"
            if notes
            else ""
        )
    )


def show_multiple_accounts_menu(service_name, entries):
    show_section_header(f"Multiple Accounts for '{service_name}'")
    for i, entry in enumerate(entries, 1):
        print(
            f"  {colors.Colors.BRIGHT_CYAN}{i}.{colors.Colors.RESET} {entry['username']}"
        )
    return prompt_input("\nSelect an account:")


def show_success(message):
    print(f"\n{colors.Colors.BRIGHT_GREEN}✓ {message}{colors.Colors.RESET}")


def show_error(message):
    print(f"\n{colors.Colors.BRIGHT_RED}✗ {message}{colors.Colors.RESET}")


def show_warning(message):
    print(f"\n{colors.Colors.BRIGHT_YELLOW}⚠ {message}{colors.Colors.RESET}")


def show_info(message):
    print(f"\n{colors.Colors.BRIGHT_BLUE}ℹ {message}{colors.Colors.RESET}")


def prompt_input(prompt_text):
    return input(
        f"{colors.Colors.BRIGHT_BLUE}❯ {prompt_text}{colors.Colors.RESET} "
    ).strip()


def show_loading(message="Processing"):
    print(
        f"{colors.Colors.BRIGHT_BLUE}⟳ {message}...{colors.Colors.RESET}",
        end="",
        flush=True,
    )


def clear_loading():
    print("\r" + " " * 50 + "\r", end="", flush=True)


def suggest_command(user_input, available_commands):
    from difflib import get_close_matches

    matches = get_close_matches(user_input, available_commands, n=1, cutoff=0.6)
    if matches:
        print(
            f"\n{colors.Colors.BRIGHT_YELLOW}Did you mean: {colors.Colors.BRIGHT_CYAN}{matches[0]}{colors.Colors.RESET}?"
        )


def show_stats(total_entries, total_services):
    print(
        f"{colors.Colors.GRAY}Vault: {total_entries} entries, {total_services} services{colors.Colors.RESET}"
    )


def display_generated_password(password: str):
    """Displays a generated password in a formatted box."""
    print(f"\n{colors.Colors.BRIGHT_CYAN}╭{'─' * 60}╮")
    print(
        f"│ {colors.Colors.BRIGHT_GREEN}Generated Password{' ' * 42}{colors.Colors.BRIGHT_CYAN}│"
    )
    print(f"├{'─' * 60}┤")
    print(
        f"│ {colors.Colors.BRIGHT_YELLOW}{password}{' ' * (59 - len(password))}{colors.Colors.BRIGHT_CYAN}│"
    )
    print(f"╰{'─' * 60}╯{colors.Colors.RESET}\n")


def show_recent_activity(entries):
    # This feature can be re-implemented if needed.
    pass


def prompt_password_masked(prompt_text="Password: "):
    """
    Prompts for a password and displays asterisks instead of the typed characters.
    Handles backspace and works on both Windows and POSIX systems.
    """
    print(
        f"{colors.Colors.BRIGHT_BLUE}❯ {prompt_text}{colors.Colors.RESET} ",
        end="",
        flush=True,
    )
    password = ""

    # Platform-specific logic to read single characters
    try:
        import platform

        if platform.system() == "Windows":
            import msvcrt

            while True:
                char = msvcrt.getch()
                if char == b"\r":  # Enter key
                    print()
                    break
                elif char == b"\x08":  # Backspace key
                    if len(password) > 0:
                        password = password[:-1]
                        # Move cursor back, print space, move cursor back again
                        print("\b \b", end="", flush=True)
                else:
                    try:
                        password += char.decode("utf-8")
                        print("*", end="", flush=True)
                    except UnicodeDecodeError:
                        pass  # Ignore characters that can't be decoded
        else:  # Linux or macOS
            import termios, tty, sys

            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)  # type: ignore
            try:
                tty.setcbreak(fd)  # type: ignore
                while True:
                    char = sys.stdin.read(1)
                    if char == "\n":  # Enter key
                        print()
                        break
                    elif char == "\x7f":  # Backspace key
                        if len(password) > 0:
                            password = password[:-1]
                            print("\b \b", end="", flush=True)
                    else:
                        password += char
                        print("*", end="", flush=True)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)  # type: ignore
        return password
    except (ImportError, ModuleNotFoundError):
        # Fallback to getpass if platform-specific modules are not available
        print("(masked input not supported, falling back to hidden)")
        import getpass

        return getpass.getpass("")
