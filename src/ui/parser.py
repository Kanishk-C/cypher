"""Initializes and configures the argparse parser for the CLI."""

import argparse
import sys
from src.ui import commands, colors


class CustomHelpFormatter(argparse.HelpFormatter):
    def format_help(self):
        help_text = super().format_help()
        return help_text.replace(
            "usage:", f"{colors.Colors.BRIGHT_YELLOW}Usage:{colors.Colors.RESET}"
        )


class CustomParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help(sys.stderr)
        sys.exit(2)


def initialize_parser():
    """Builds and returns the argparse parser with all commands."""
    parser = CustomParser(
        description="Cypher - Secure Local Password Manager",
        formatter_class=CustomHelpFormatter,
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="help", help="Show this help message")

    subparsers = parser.add_subparsers(title="Available Commands", metavar="<command>")

    # Add
    add = subparsers.add_parser(
        "add",
        aliases=["a"],
        help="Add a new password entry",
        formatter_class=CustomHelpFormatter,
    )
    add.add_argument("service", nargs="?", help="Service name")
    add.add_argument("username", nargs="?", help="Username or email")
    add.set_defaults(func=commands.add_command)

    # Get
    get = subparsers.add_parser(
        "get",
        aliases=["g"],
        help="Retrieve a password",
        formatter_class=CustomHelpFormatter,
    )
    get.add_argument("service", help="Service name")
    get.add_argument("username", nargs="?", help="Username (if multiple accounts)")
    get.set_defaults(func=commands.get_command)

    # List
    list_cmd = subparsers.add_parser(
        "list",
        aliases=["ls"],
        help="List all entries",
        formatter_class=CustomHelpFormatter,
    )
    list_cmd.set_defaults(func=commands.list_command)

    # Delete
    delete = subparsers.add_parser(
        "delete",
        aliases=["rm"],
        help="Delete an entry",
        formatter_class=CustomHelpFormatter,
    )
    delete.add_argument("service", help="Service name")
    delete.add_argument("username", help="Username")
    delete.add_argument(
        "-f", "--force", action="store_true", help="Delete without confirmation"
    )
    delete.set_defaults(func=commands.delete_command)

    # Search
    search = subparsers.add_parser(
        "search",
        aliases=["s"],
        help="Search for entries",
        formatter_class=CustomHelpFormatter,
    )
    search.add_argument("query", nargs="?", help="Search term")
    search.set_defaults(func=commands.search_command)

    # Generate
    generate = subparsers.add_parser(
        "generate",
        aliases=["gen"],
        help="Generate a secure password",
        formatter_class=CustomHelpFormatter,
    )
    generate.set_defaults(func=commands.generate_password_command)

    # Switch
    switch = subparsers.add_parser(
        "switch", help="Switch to another profile", formatter_class=CustomHelpFormatter
    )
    switch.set_defaults(func=commands.switch_command)
    # Clear
    clear = subparsers.add_parser(
        "clear",
        aliases=["cls", "c"],
        help="Clear the terminal screen",
        formatter_class=CustomHelpFormatter,
    )
    clear.set_defaults(func=commands.clear_command)

    return parser
