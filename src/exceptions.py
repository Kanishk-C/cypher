# File: src/exceptions.py
"""Custom exceptions for application domain logic."""

import logging


class CoreException(Exception):
    """Base exception for core errors that automatically logs the error message."""

    def __init__(self, message: str):
        self.message = message
        logging.error(f"{self.__class__.__name__}: {message}")
        super().__init__(self.message)


class EntryNotFoundError(CoreException):
    """Raised when a specific entry cannot be found."""

    pass


class EntryNotFoundWithSuggestionError(CoreException):
    """Raised when an entry is not found, but a similar entry exists."""

    pass


class DuplicateEntryError(CoreException):
    """Raised when attempting to add an entry that already exists."""

    pass


class DecryptionError(CoreException):
    """Raised when data decryption fails, indicating a potential key issue or data corruption."""

    pass


class DatabaseError(CoreException):
    """Raised for general database operational errors."""

    pass
