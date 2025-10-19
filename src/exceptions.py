"""Custom exceptions for application."""

import logging


class CoreException(Exception):
    """Base exception that logs errors."""

    def __init__(self, message: str):
        self.message = message
        logging.error(f"{self.__class__.__name__}: {message}")
        super().__init__(self.message)


class EntryNotFoundError(CoreException):
    """Entry not found."""

    pass


class DuplicateEntryError(CoreException):
    """Entry already exists."""

    pass


class DecryptionError(CoreException):
    """Decryption failed."""

    pass


class DatabaseError(CoreException):
    """Database operation error."""

    pass
