# File: src/interface/colors.py
"""ANSI color codes for terminal output."""

import platform
import os

# Initialize color support for Windows terminals
if platform.system() == "Windows":
    os.system("")  # Enables ANSI escape sequences in Windows 10/11 terminals


class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"

    # Standard colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright colors
    BRIGHT_BLACK = "\033[90m"  # Also known as "gray"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Aliases for common uses
    GRAY = BRIGHT_BLACK
    GREY = BRIGHT_BLACK
    DIM = "\033[2m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"