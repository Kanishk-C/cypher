"""Initializes and configures the argparse parser for the CLI - v1.0.0 PRODUCTION READY."""

import argparse
import sys
from src.ui import commands, colors
from src.config import Config


class CustomHelpFormatter(argparse.HelpFormatter):
    """Custom formatter that colorizes help text."""

    def format_help(self):
        """Add color to usage line."""
        help_text = super().format_help()
        return help_text.replace(
            "usage:", f"{colors.Colors.BRIGHT_YELLOW}Usage:{colors.Colors.RESET}"
        )


class CustomParser(argparse.ArgumentParser):
    """Custom parser that shows help on error instead of just error message."""

    def error(self, message):
        """Show help message when command parsing fails."""
        sys.stderr.write(
            f"{colors.Colors.ERROR}Error: {message}{colors.Colors.RESET}\n\n"
        )
        self.print_help(sys.stderr)
        sys.exit(2)


def initialize_parser():
    """
    Build and return the argparse parser with all commands.

    Available commands:
    - add: Add new password entry
    - get: Retrieve password
    - list: List all entries
    - delete: Delete entry
    - update: Update existing entry
    - search: Search entries
    - generate: Generate secure password
    - export: Export profile backup
    - clear: Clear screen
    - switch: Switch profile
    - delete-profile: Delete profile permanently

    Returns:
        Configured ArgumentParser instance
    """
    parser = CustomParser(
        prog="cypher",
        description=f"{Config.APP_NAME} v{Config.VERSION} - Secure Local Password Manager",
        formatter_class=CustomHelpFormatter,
        add_help=False,
    )

    # Global help argument
    parser.add_argument(
        "-h", "--help", action="help", help="Show this help message and exit"
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"{Config.APP_NAME} v{Config.VERSION}",
        help="Show version information and exit",
    )

    # Subcommand parsers
    subparsers = parser.add_subparsers(
        title="Available Commands", metavar="<command>", dest="command"
    )

    # ========================================
    # ADD COMMAND
    # ========================================
    add = subparsers.add_parser(
        "add",
        aliases=["a"],
        help="Add a new password entry",
        description="Add a new password entry to your vault",
        formatter_class=CustomHelpFormatter,
    )
    add.add_argument("service", nargs="?", help="Service name (e.g., github, gmail)")
    add.add_argument("username", nargs="?", help="Username or email address")
    add.set_defaults(func=commands.add_command)

    # ========================================
    # GET COMMAND
    # ========================================
    get = subparsers.add_parser(
        "get",
        aliases=["g"],
        help="Retrieve a password",
        description="Retrieve and display a password from your vault",
        formatter_class=CustomHelpFormatter,
    )
    get.add_argument("service", help="Service name")
    get.add_argument(
        "username",
        nargs="?",
        help="Username (required if multiple accounts exist for service)",
    )
    get.set_defaults(func=commands.get_command)

    # ========================================
    # LIST COMMAND
    # ========================================
    list_cmd = subparsers.add_parser(
        "list",
        aliases=["ls"],
        help="List all entries",
        description="List all password entries in your vault",
        formatter_class=CustomHelpFormatter,
    )
    list_cmd.set_defaults(func=commands.list_command)

    # ========================================
    # DELETE COMMAND
    # ========================================
    delete = subparsers.add_parser(
        "delete",
        aliases=["rm", "del"],
        help="Delete an entry",
        description="Permanently delete a password entry",
        formatter_class=CustomHelpFormatter,
    )
    delete.add_argument("service", help="Service name")
    delete.add_argument("username", help="Username")
    delete.add_argument(
        "-f", "--force", action="store_true", help="Delete without confirmation prompt"
    )
    delete.set_defaults(func=commands.delete_command)

    # ========================================
    # UPDATE COMMAND
    # ========================================
    update = subparsers.add_parser(
        "update",
        aliases=["edit", "modify"],
        help="Update an existing entry",
        description="Update password or notes for an existing entry",
        formatter_class=CustomHelpFormatter,
    )
    update.add_argument("service", help="Service name")
    update.add_argument("username", help="Username")
    update.set_defaults(func=commands.update_command)

    # ========================================
    # SEARCH COMMAND
    # ========================================
    search = subparsers.add_parser(
        "search",
        aliases=["find", "s"],
        help="Search for entries",
        description="Search for entries by service name (case-insensitive)",
        formatter_class=CustomHelpFormatter,
    )
    search.add_argument("query", nargs="?", help="Search term (partial service name)")
    search.set_defaults(func=commands.search_command)

    # ========================================
    # GENERATE COMMAND
    # ========================================
    generate = subparsers.add_parser(
        "generate",
        aliases=["gen", "password"],
        help="Generate a secure password",
        description="Generate a cryptographically secure random password",
        formatter_class=CustomHelpFormatter,
    )
    generate.add_argument(
        "-l",
        "--length",
        type=int,
        default=16,
        help="Password length (default: 16, min: 8, max: 128)",
    )
    generate.add_argument(
        "--no-uppercase", action="store_true", help="Exclude uppercase letters"
    )
    generate.add_argument(
        "--no-lowercase", action="store_true", help="Exclude lowercase letters"
    )
    generate.add_argument("--no-digits", action="store_true", help="Exclude digits")
    generate.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
    generate.set_defaults(func=commands.generate_password_command)

    # ========================================
    # EXPORT COMMAND
    # ========================================
    export = subparsers.add_parser(
        "export",
        aliases=["backup"],
        help="Export encrypted profile backup",
        description="Create an encrypted backup of your current profile",
        formatter_class=CustomHelpFormatter,
    )
    export.add_argument(
        "export_path",
        nargs="?",
        help="Export file path (default: <profile>_backup_<timestamp>.cypher)",
    )
    export.set_defaults(func=commands.export_profile_command)

    # ========================================
    # SWITCH COMMAND
    # ========================================
    switch = subparsers.add_parser(
        "switch",
        aliases=["logout"],
        help="Switch to another profile",
        description="Log out of current profile and return to profile selection",
        formatter_class=CustomHelpFormatter,
    )
    switch.set_defaults(func=commands.switch_command)

    # ========================================
    # CLEAR COMMAND
    # ========================================
    clear = subparsers.add_parser(
        "clear",
        aliases=["cls", "c"],
        help="Clear the terminal screen",
        description="Clear the terminal and redisplay the header",
        formatter_class=CustomHelpFormatter,
    )
    clear.set_defaults(func=commands.clear_command)

    # ========================================
    # DELETE-PROFILE COMMAND
    # ========================================
    delete_profile = subparsers.add_parser(
        "delete-profile",
        aliases=["remove-profile"],
        help="Permanently delete a profile",
        description="Permanently delete a profile and all its data (IRREVERSIBLE)",
        formatter_class=CustomHelpFormatter,
    )
    delete_profile.add_argument("profile_name", help="Name of the profile to delete")
    delete_profile.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Skip confirmation prompts (dangerous)",
    )
    delete_profile.set_defaults(func=commands.delete_profile_command)

    return parser


def get_command_list():
    """
    Get list of all available commands.

    Useful for command suggestion and completion.

    Returns:
        List of command names (including aliases)
    """
    return [
        "add",
        "a",
        "get",
        "g",
        "list",
        "ls",
        "delete",
        "rm",
        "del",
        "update",
        "edit",
        "modify",
        "search",
        "find",
        "s",
        "generate",
        "gen",
        "password",
        "export",
        "backup",
        "switch",
        "logout",
        "clear",
        "cls",
        "c",
        "delete-profile",
        "remove-profile",
        "help",
        "exit",
        "quit",
        "q",
    ]


def print_quick_help():
    """
    Print a quick reference of common commands.

    This is a simplified help shown when users first log in.
    """
    print(f"\n{colors.Colors.HEADER}Quick Reference{colors.Colors.RESET}\n")

    commands_help = [
        ("add [service] [username]", "Add a new password"),
        ("get <service> [username]", "Retrieve a password"),
        ("list", "List all entries"),
        ("search <query>", "Search entries"),
        ("generate", "Generate secure password"),
        ("export [path]", "Backup your profile"),
        ("help", "Show detailed help"),
        ("exit", "Exit application"),
    ]

    for cmd, desc in commands_help:
        print(f"  {colors.Colors.PRIMARY}{cmd:<25}{colors.Colors.RESET} {desc}")

    print()


if __name__ == "__main__":
    """
    Test the parser when run directly.
    """
    parser = initialize_parser()

    print(f"{Config.APP_NAME} v{Config.VERSION}")
    print("=" * 50)
    print("\nAvailable commands:")

    commands_list = get_command_list()
    # Remove duplicates while preserving order
    seen = set()
    unique_commands = []
    for cmd in commands_list:
        if cmd not in seen and len(cmd) > 1:  # Skip single-letter aliases for display
            seen.add(cmd)
            unique_commands.append(cmd)

    for cmd in sorted(unique_commands):
        print(f"  - {cmd}")

    print("\nRun 'cypher --help' for detailed usage information.")
