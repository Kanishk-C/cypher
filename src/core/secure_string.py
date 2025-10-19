"""Secure string handling for passwords."""

import gc


class SecureString:
    """
    Secure string wrapper that attempts to clear memory on deletion.
    Note: Python's immutability makes true secure strings difficult.
    """

    def __init__(self, value: str):
        self._value = bytearray(value.encode("utf-8"))
        self._cleared = False

    def get(self) -> str:
        """Get the string value."""
        if self._cleared:
            raise ValueError("SecureString has been cleared")
        return self._value.decode("utf-8")

    def clear(self):
        """Clear the string from memory."""
        if self._cleared:
            return
        # Overwrite with zeros to scrub the memory
        for i in range(len(self._value)):
            self._value[i] = 0
        self._value.clear()
        self._cleared = True
        gc.collect()

    def __del__(self):
        """Ensure cleanup when the object is garbage collected."""
        self.clear()

    def __enter__(self):
        """Enter the context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context manager, ensuring cleanup."""
        self.clear()

    def __str__(self):
        """Prevent accidental logging or printing of the secret."""
        return "SecureString(***)"

    def __repr__(self):
        """Provide a safe representation of the object."""
        return "SecureString(***)"
