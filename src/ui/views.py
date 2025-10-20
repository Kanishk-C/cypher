"""Handles all user-facing output and display formatting."""

import os
import platform
import shutil
import re
from src.ui.colors import Colors
from src.config import Config
from src.core.crypto import InputLimits


def get_terminal_width():
    """Get the current terminal width."""
    try:
        width = shutil.get_terminal_size().columns
        # Minimum width: 60, Maximum width: 120
        return max(60, min(width, Config.TERMINAL_MAX_WIDTH))
    except:
        return 80  # Safe fallback


def show_banner():
    """Displays application banner with gradient effect."""
    banner = [
        "   ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗ ",
        "  ██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗",
        "  ██║      ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝",
        "  ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗",
        "  ╚██████╗   ██║   ██║     ██║  ██║███████╗██║  ██║",
        "   ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
    ]

    # Gradient: cyan -> blue -> magenta
    gradient_colors = [
        Colors.BRIGHT_CYAN,
        Colors.BRIGHT_CYAN,
        Colors.PRIMARY,
        Colors.BRIGHT_BLUE,
        Colors.SECONDARY,
        Colors.ACCENT,
    ]
    terminal_width = get_terminal_width()

    for i, line in enumerate(banner):
        color = gradient_colors[i]
        if len(line) <= terminal_width:
            print(f"{color}{line.center(terminal_width)}{Colors.RESET}")
        else:
            print(f"{color}{line}{Colors.RESET}")

    tagline = "Secure Local Password Management"
    if len(tagline) <= terminal_width:
        print(f"\n{Colors.MUTED}{tagline.center(terminal_width)}{Colors.RESET}\n")
    else:
        print(f"\n{Colors.MUTED}{tagline}{Colors.RESET}\n")


def show_profile_header(profile_name):
    """Enhanced profile header with responsive sizing."""
    terminal_width = get_terminal_width()
    box_width = min(terminal_width - 4, 80)
    border = "─" * (box_width - 2)

    print(f"\n{Colors.PRIMARY}┌{border}┐{Colors.RESET}")

    profile_text = f"Profile: {profile_name}"
    text_len = len(profile_text)

    if text_len < box_width - 4:
        padding = box_width - text_len - 4
        print(
            f"{Colors.PRIMARY}│ {Colors.LABEL}Profile: "
            f"{Colors.SUCCESS}{profile_name}{Colors.PRIMARY}"
            f"{' ' * padding} │{Colors.RESET}"
        )
    else:
        max_name_len = box_width - 14
        truncated = (
            profile_name[:max_name_len] + "..."
            if len(profile_name) > max_name_len
            else profile_name
        )
        padding = box_width - len(f"Profile: {truncated}") - 4
        print(
            f"{Colors.PRIMARY}│ {Colors.LABEL}Profile: "
            f"{Colors.SUCCESS}{truncated}{Colors.PRIMARY}"
            f"{' ' * padding} │{Colors.RESET}"
        )

    print(f"{Colors.PRIMARY}└{border}┘{Colors.RESET}")


def show_section_header(title):
    """Enhanced section headers with responsive width."""
    terminal_width = get_terminal_width()
    max_width = min(terminal_width - 4, 80)

    if len(title) + 8 <= max_width:
        print(f"\n{Colors.HEADER}─── {title} ───{Colors.RESET}")
    else:
        print(f"\n{Colors.HEADER}{title}{Colors.RESET}")


def show_quick_help():
    """Simple, clean quick help in single column with auto-resize."""
    print(f"\n{Colors.HEADER}Available Commands{Colors.RESET}\n")

    commands_data = [
        ("add", "Add a new password"),
        ("get", "Retrieve a password"),
        ("list", "List all entries"),
        ("delete", "Delete an entry"),
        ("update", "Update an entry"),
        ("search", "Search for entries"),
        ("generate", "Generate secure password"),
        ("clear", "Clear the screen"),
        ("switch", "Switch to another profile"),
        ("help", "Show detailed help"),
        ("exit", "Exit application"),
    ]

    terminal_width = get_terminal_width()

    for cmd, desc in commands_data:
        if terminal_width < 60:
            print(f"  {Colors.PRIMARY}{cmd}{Colors.RESET}")
        elif terminal_width < 80:
            max_desc_len = terminal_width - 18
            truncated_desc = (
                desc[:max_desc_len] + "..." if len(desc) > max_desc_len else desc
            )
            print(f"  {Colors.PRIMARY}{cmd:<12}{Colors.RESET} {truncated_desc}")
        else:
            print(f"  {Colors.PRIMARY}{cmd:<12}{Colors.RESET} {desc}")

    print(f"\n{Colors.MUTED}Type any command to get started{Colors.RESET}\n")


def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")


def confirm_action(prompt: str) -> bool:
    response = input(f"{Colors.BRIGHT_YELLOW}❯ {prompt} (y/N):{Colors.RESET} ").lower()
    return response == "y"


def display_profile_list(profiles):
    """Enhanced profile list display with responsive width."""
    terminal_width = get_terminal_width()

    profile_parts = []
    for p in profiles:
        profile_parts.append(f"{Colors.SUCCESS}{p}{Colors.RESET}")

    profile_str = ", ".join(profile_parts)
    prefix = f"{Colors.PRIMARY}Available Profiles: {Colors.RESET}"

    visible_len = len("Available Profiles: ") + sum(len(p) + 2 for p in profiles)

    if visible_len <= terminal_width - 4:
        print(f"{prefix}{profile_str}\n")
    else:
        print(f"{prefix}")
        for p in profiles:
            print(f"  • {Colors.SUCCESS}{p}{Colors.RESET}")
        print()


def display_entry_list(entries, search_term: str = ""):
    """Enhanced entry list with responsive width."""
    show_section_header("Saved Credentials")
    if not entries:
        print(f"{Colors.WARNING}  No entries found.{Colors.RESET}")
        return

    terminal_width = get_terminal_width()

    for service, username in entries:
        display_service = service
        if search_term:
            display_service = re.sub(
                f"({re.escape(search_term)})",
                f"{Colors.HIGHLIGHT}\\1{Colors.RESET}",
                service,
                flags=re.IGNORECASE,
            )

        max_service_len = terminal_width - 25
        max_username_len = 20

        if len(service) > max_service_len:
            display_service = service[: max_service_len - 3] + "..."

        username_display = username
        if len(username) > max_username_len:
            username_display = username[: max_username_len - 3] + "..."

        print(
            f"  {Colors.PRIMARY}● {Colors.RESET}"
            f"{Colors.SERVICE}{display_service}{Colors.RESET} "
            f"({Colors.USERNAME}{username_display}{Colors.RESET})"
        )


def display_entry_details(service, username, password, notes):
    """Enhanced entry display with responsive sizing."""
    terminal_width = get_terminal_width()
    box_width = min(terminal_width - 4, 70)

    print(f"\n{Colors.PRIMARY}╭{'─' * box_width}╮")

    header = "Password Entry"
    header_padding = box_width - len(header) - 2
    print(
        f"│ {Colors.HEADER}{header}{Colors.PRIMARY}"
        f"{' ' * header_padding}│{Colors.RESET}"
    )
    print(f"{Colors.PRIMARY}├{'─' * box_width}┤{Colors.RESET}")

    def print_field(label, value, value_color):
        max_value_len = box_width - len(label) - 4
        if len(value) > max_value_len:
            value_display = value[: max_value_len - 3] + "..."
        else:
            value_display = value

        padding = box_width - len(label) - len(value_display) - 2
        print(
            f"{Colors.PRIMARY}│ {Colors.LABEL}{label} {Colors.RESET}"
            f"{value_color}{value_display}{Colors.RESET}"
            f"{' ' * padding}{Colors.PRIMARY}│{Colors.RESET}"
        )

    print_field("Service: ", service, Colors.SERVICE)
    print_field("Username:", username, Colors.USERNAME)
    print_field("Password:", password, Colors.PASSWORD)

    if notes:
        max_note_len = box_width - 13
        note_lines = notes.split("\n")

        for i, line in enumerate(note_lines[:3]):
            if i == 0:
                label = f"{Colors.LABEL}Notes:    {Colors.RESET}"
                label_len = 10
            else:
                label = " " * 10
                label_len = 10

            if len(line) > max_note_len:
                line_display = line[: max_note_len - 3] + "..."
            else:
                line_display = line

            padding = box_width - label_len - len(line_display) - 2
            print(
                f"{Colors.PRIMARY}│ {label}"
                f"{Colors.NOTES}{line_display}{Colors.RESET}"
                f"{' ' * padding}{Colors.PRIMARY}│{Colors.RESET}"
            )

        if len(note_lines) > 3:
            ellipsis = "... (truncated)"
            padding = box_width - 10 - len(ellipsis) - 2
            print(
                f"{Colors.PRIMARY}│ {' ' * 10}"
                f"{Colors.MUTED}{ellipsis}{Colors.RESET}"
                f"{' ' * padding}{Colors.PRIMARY}│{Colors.RESET}"
            )

    print(f"{Colors.PRIMARY}╰{'─' * box_width}╯{Colors.RESET}\n")


def show_multiple_accounts_menu(service_name, entries):
    """Enhanced multiple accounts menu with responsive sizing."""
    show_section_header(f"Multiple Accounts for '{service_name}'")

    terminal_width = get_terminal_width()
    max_username_len = terminal_width - 10

    for i, entry in enumerate(entries, 1):
        username = entry["username"]
        if len(username) > max_username_len:
            username_display = username[: max_username_len - 3] + "..."
        else:
            username_display = username

        print(
            f"  {Colors.PRIMARY}{i}.{Colors.RESET} "
            f"{Colors.USERNAME}{username_display}{Colors.RESET}"
        )
    return prompt_input("\nSelect an account:")


def show_success(message):
    """Success message with icon."""
    print(f"\n{Colors.SUCCESS}✓ {message}{Colors.RESET}")


def show_error(message):
    """Error message with icon."""
    print(f"\n{Colors.ERROR}✗ {message}{Colors.RESET}")


def show_warning(message):
    """Warning message with icon."""
    print(f"\n{Colors.WARNING}⚠ {message}{Colors.RESET}")


def show_info(message):
    """Info message with icon."""
    print(f"\n{Colors.INFO}ℹ {message}{Colors.RESET}")


def prompt_input(prompt_text):
    """Enhanced input prompt."""
    return input(f"{Colors.PROMPT}❯ {prompt_text}{Colors.RESET} ").strip()


def show_loading(message="Processing"):
    print(
        f"{Colors.BRIGHT_BLUE}⟳ {message}...{Colors.RESET}",
        end="",
        flush=True,
    )


def clear_loading():
    print("\r" + " " * 50 + "\r", end="", flush=True)


def suggest_command(user_input, available_commands):
    """Enhanced command suggestion."""
    from difflib import get_close_matches

    matches = get_close_matches(user_input, available_commands, n=1, cutoff=0.6)
    if matches:
        print(
            f"\n{Colors.WARNING}Did you mean: "
            f"{Colors.PRIMARY}{matches[0]}{Colors.RESET}?"
        )
    else:
        print(
            f"\n{Colors.ERROR}Unknown command: {Colors.MUTED}'{user_input}'{Colors.RESET}"
        )
        print(f"{Colors.INFO}Type 'help' for available commands.{Colors.RESET}")


def show_stats(total_entries, total_services):
    print(
        f"{Colors.GRAY}Vault: {total_entries} entries, {total_services} services{Colors.RESET}"
    )


def display_generated_password(password: str):
    """Enhanced generated password display with responsive sizing."""
    terminal_width = get_terminal_width()
    box_width = min(terminal_width - 4, 70)

    print(f"\n{Colors.PRIMARY}╭{'─' * box_width}╮")

    header = "Generated Password"
    header_padding = box_width - len(header) - 2
    print(
        f"│ {Colors.HEADER}{header}{Colors.PRIMARY}"
        f"{' ' * header_padding}│{Colors.RESET}"
    )
    print(f"{Colors.PRIMARY}├{'─' * box_width}┤{Colors.RESET}")

    if len(password) <= box_width - 4:
        padding = box_width - len(password) - 2
        print(
            f"{Colors.PRIMARY}│ {Colors.PASSWORD}{password}{Colors.RESET}"
            f"{' ' * padding}{Colors.PRIMARY}│{Colors.RESET}"
        )
    else:
        chunk_size = box_width - 4
        for i in range(0, len(password), chunk_size):
            chunk = password[i : i + chunk_size]
            padding = box_width - len(chunk) - 2
            print(
                f"{Colors.PRIMARY}│ {Colors.PASSWORD}{chunk}{Colors.RESET}"
                f"{' ' * padding}{Colors.PRIMARY}│{Colors.RESET}"
            )

    print(f"{Colors.PRIMARY}╰{'─' * box_width}╯{Colors.RESET}\n")

    strength = "Strong" if len(password) >= 16 else "Medium"
    strength_color = Colors.SUCCESS if len(password) >= 16 else Colors.WARNING
    print(f"{Colors.MUTED}Strength: {strength_color}{strength}{Colors.RESET}\n")


def show_recent_activity(entries):
    # This feature can be re-implemented if needed.
    pass


def prompt_password_masked(prompt_text="Password: "):
    """
    Prompts for a password with length limit.
    """
    print(
        f"{Colors.BRIGHT_BLUE}❯ {prompt_text}{Colors.RESET} ",
        end="",
        flush=True,
    )
    password = ""
    max_length = InputLimits.MAX_PASSWORD_LENGTH

    try:
        if platform.system() == "Windows":
            import msvcrt

            while True:
                char = msvcrt.getch()
                if char == b"\r":
                    print()
                    break
                elif char == b"\x08":
                    if len(password) > 0:
                        password = password[:-1]
                        print("\b \b", end="", flush=True)
                else:
                    try:
                        if len(password) >= max_length:
                            continue
                        password += char.decode("utf-8")
                        print("*", end="", flush=True)
                    except UnicodeDecodeError:
                        pass
        else:  # Linux or macOS
            import termios, tty, sys

            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)  # type: ignore
            try:
                tty.setcbreak(fd)  # pyright: ignore[reportAttributeAccessIssue]
                while True:
                    char = sys.stdin.read(1)
                    if char == "\n":
                        print()
                        break
                    elif char == "\x7f":
                        if len(password) > 0:
                            password = password[:-1]
                            print("\b \b", end="", flush=True)
                    else:
                        if len(password) >= max_length:
                            continue
                        password += char
                        print("*", end="", flush=True)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)  # type: ignore
        return password
    except (ImportError, ModuleNotFoundError):
        import getpass

        return getpass.getpass("")
