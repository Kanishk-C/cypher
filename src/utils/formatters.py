"""Reusable formatting utilities."""

from interface import colors
import shutil


class UIFormatter:
    """Centralized UI formatting logic."""
    
    @staticmethod
    def get_terminal_width(max_width: int = 120) -> int:
        """Get terminal width with bounds."""
        try:
            width = shutil.get_terminal_size().columns
            return min(width, max_width)
        except:
            return 80
    
    @staticmethod
    def format_box(title: str, content: dict, width: int = None) -> str:
        """Create a formatted box for displaying data."""
        if width is None:
            width = min(UIFormatter.get_terminal_width(), 70)
        
        lines = []
        lines.append(f"{colors.Colors.BRIGHT_CYAN}╭{'─' * (width - 2)}╮")
        
        title_padding = width - len(title) - 3
        lines.append(f"│ {colors.Colors.BRIGHT_GREEN}{title}{colors.Colors.BRIGHT_CYAN}{' ' * title_padding}│")
        lines.append(f"├{'─' * (width - 2)}┤")
        
        for key, value in content.items():
            # Handle special coloring for passwords
            if key.lower() == "password":
                display = f"{key}: {colors.Colors.BRIGHT_GREEN}{value}{colors.Colors.BRIGHT_BLUE}"
                visible_len = len(f"{key}: {value}")
            else:
                display = f"{key}: {value}"
                visible_len = len(display)
            
            padding = width - visible_len - 3
            lines.append(f"│ {colors.Colors.BRIGHT_BLUE}{display}{colors.Colors.BRIGHT_CYAN}{' ' * padding}│")
        
        lines.append(f"╰{'─' * (width - 2)}╯{colors.Colors.RESET}")
        return '\n'.join(lines)
    
    @staticmethod
    def format_table(headers: list, rows: list) -> str:
        """Format data as a table."""
        if not rows:
            return ""
        
        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Build table
        lines = []
        
        # Header
        header_line = "  ".join(h.ljust(w) for h, w in zip(headers, col_widths))
        lines.append(f"{colors.Colors.BRIGHT_CYAN}{header_line}{colors.Colors.RESET}")
        lines.append(f"{colors.Colors.BRIGHT_BLACK}{'─' * len(header_line)}{colors.Colors.RESET}")
        
        # Rows
        for row in rows:
            row_line = "  ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths))
            lines.append(f"{colors.Colors.RESET}{row_line}")
        
        return '\n'.join(lines)
