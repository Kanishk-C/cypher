"""Initializes and configures the argparse parser for the CLI."""

import argparse
import sys
import logging
from . import handlers, colors


class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, max_help_position=30)

    def format_help(self):
        raw_help = super().format_help()
        styled_help = raw_help.replace('usage:', f'{colors.Colors.BRIGHT_YELLOW}Usage:{colors.Colors.RESET}')
        styled_help = styled_help.replace('positional arguments:',
                                          f'\n{colors.Colors.BRIGHT_YELLOW}Arguments:{colors.Colors.RESET}')
        styled_help = styled_help.replace('options:', f'\n{colors.Colors.BRIGHT_YELLOW}Options:{colors.Colors.RESET}')
        return styled_help


class CustomParser(argparse.ArgumentParser):
    def error(self, message):
        """Overrides the default error handler."""
        logging.error(f"Command parse error: {message}")
        command = self.prog.replace('cypher ', '')
        print(f"\n{colors.Colors.BRIGHT_RED}✗ Invalid command usage: {message}{colors.Colors.RESET}")
        print(f"  {colors.Colors.GRAY}For correct usage, run: {colors.Colors.BRIGHT_CYAN}{command} --help{colors.Colors.RESET}")
        sys.exit(1)


def initialize_parser():
    """Builds and returns the argparse parser with all commands."""
    parser = CustomParser(
        description=f"{colors.Colors.BRIGHT_CYAN}Cypher{colors.Colors.RESET} - Secure Local Password Manager",
        formatter_class=CustomHelpFormatter,
        add_help=False,
        prog="cypher"
    )
    parser.add_argument('-h', '--help', action='help', help='Show this help message')

    subparsers = parser.add_subparsers(
        title="Available Commands",
        metavar="<command>",
    )

    # Add command
    add = subparsers.add_parser("add", aliases=["a"], help="Add a new password entry",
                                formatter_class=CustomHelpFormatter, prog="cypher add")
    add.add_argument("service", nargs="?", help="Service name (e.g., 'google', 'github')")
    add.add_argument("username", nargs="?", help="Username or email for the service")
    add.set_defaults(func=handlers.add_command)

    # Clear command
    clear = subparsers.add_parser("clear", aliases=["cls", "c"], help="Clear the terminal screen",
                                  formatter_class=CustomHelpFormatter, prog="cypher clear")
    clear.set_defaults(func=handlers.clear_command)

    # Delete command
    delete = subparsers.add_parser("delete", aliases=["d", "del", "rm"], help="Delete a password entry",
                                   formatter_class=CustomHelpFormatter, prog="cypher delete")
    delete.add_argument("service", help="Service name of the entry to delete")
    delete.add_argument("username", help="Username of the entry to delete")
    delete.add_argument("-f", "--force", action="store_true", help="Delete without confirmation")
    delete.set_defaults(func=handlers.delete_command)

    # Get command
    get = subparsers.add_parser("get", aliases=["g", "show"], help="Retrieve a password for a service",
                                formatter_class=CustomHelpFormatter, prog="cypher get")
    get.add_argument("service", help="Service name to search for")
    get.add_argument("username", nargs="?", help="Username (if multiple accounts exist)")
    get.set_defaults(func=handlers.get_command)

    # List command
    list_cmd = subparsers.add_parser("list", aliases=["l", "ls"], help="List all stored services",
                                     formatter_class=CustomHelpFormatter, prog="cypher list")
    list_cmd.set_defaults(func=handlers.list_command)

    # Update command
    update = subparsers.add_parser("update", aliases=["u", "edit"], help="Update an existing password entry",
                                   formatter_class=CustomHelpFormatter, prog="cypher update")
    update.add_argument("service", help="Service name of the entry to update")
    update.add_argument("username", help="Username of the entry to update")
    update.set_defaults(func=handlers.update_command)

    # Search command
    search = subparsers.add_parser("search", aliases=["s", "find"], help="Search for entries by service name",
                                   formatter_class=CustomHelpFormatter, prog="cypher search")
    search.add_argument("query", nargs="?", help="Search term (partial service name)")
    search.set_defaults(func=handlers.search_command)

    # Generate password command
    generate = subparsers.add_parser("generate", aliases=["gen", "passwd"], help="Generate a secure random password",
                                     formatter_class=CustomHelpFormatter, prog="cypher generate")
    generate.set_defaults(func=handlers.generate_password_command)

    # Restart command
    restart = subparsers.add_parser("restart", aliases=["reload", "switch"],
                                    help="Log out and switch to another profile",
                                    formatter_class=CustomHelpFormatter, prog="cypher restart")
    restart.set_defaults(func=handlers.restart_command)

    return parser

