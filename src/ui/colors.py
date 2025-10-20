"""Enhanced ANSI color codes with semantic meanings and visual hierarchy."""

import platform
import os

# Initialize color support for Windows terminals
if platform.system() == "Windows":
    os.system("")  # Enables ANSI escape sequences in Windows 10/11 terminals


class Colors:
    """Enhanced ANSI color codes with semantic naming for better UX."""

    RESET = "\033[0m"

    # Standard colors (rarely used directly)
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright colors (base palette)
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Text modifiers
    GRAY = BRIGHT_BLACK
    GREY = BRIGHT_BLACK
    DIM = "\033[2m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"

    # ========== SEMANTIC COLORS - USE THESE FOR CONSISTENCY ==========

    # Primary Brand Colors
    PRIMARY = "\033[96m"  # Bright Cyan - Main brand/interactive
    SECONDARY = "\033[94m"  # Bright Blue - Secondary elements
    ACCENT = "\033[95m"  # Bright Magenta - Special highlights

    # Status Colors (Clear semantic meaning)
    SUCCESS = "\033[92m"  # Bright Green - Success, completion
    ERROR = "\033[91m"  # Bright Red - Errors, failures
    WARNING = "\033[93m"  # Bright Yellow - Warnings, cautions
    INFO = "\033[94m"  # Bright Blue - Information, hints

    # UI Component Colors
    PROMPT = "\033[96m"  # Bright Cyan - Input prompts
    INPUT = "\033[97m"  # Bright White - User input text
    HEADER = "\033[1m\033[96m"  # Bold Cyan - Section headers
    SUBHEADER = "\033[94m"  # Bright Blue - Subsections
    BORDER = "\033[90m"  # Gray - UI borders, decorative

    # Data Display Colors
    LABEL = "\033[96m"  # Bright Cyan - Field labels
    VALUE = "\033[97m"  # Bright White - Field values
    PASSWORD = "\033[92m"  # Bright Green - Passwords (when shown)
    SERVICE = "\033[96m"  # Bright Cyan - Service names
    USERNAME = "\033[94m"  # Bright Blue - Username/email
    NOTES = "\033[90m"  # Gray - Notes, metadata

    # Special Purpose
    MUTED = "\033[90m"  # Gray - Less important text
    HIGHLIGHT = "\033[1m\033[93m"  # Bold Yellow - Important highlights
    CRITICAL = "\033[1m\033[91m"  # Bold Red - Critical warnings
    LINK = "\033[4m\033[94m"  # Underline Blue - Links/references
