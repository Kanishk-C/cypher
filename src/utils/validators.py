"""Reusable validation utilities."""

import re
import math
from collections import Counter
from typing import Tuple
from src.config import Config
from src.core.crypto import InputLimits


class InputValidator:
    """Centralized input validation with security fixes."""

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        counter = Counter(text.lower())
        length = len(text)

        entropy = -sum(
            (count / length) * math.log2(count / length) for count in counter.values()
        )

        return entropy * length

    @staticmethod
    def validate_service_name(service: str) -> Tuple[bool, str]:
        """Validate service name format - FIXED."""
        if not service or not service.strip():
            return False, "Service name cannot be empty"

        if len(service) > Config.MAX_SERVICE_NAME_LENGTH:
            return (
                False,
                f"Service name too long (max {Config.MAX_SERVICE_NAME_LENGTH})",
            )

        if "\x00" in service:
            return False, "Service name contains invalid null byte"

        if not re.match(r"^[a-zA-Z0-9\s\-_.@]+$", service):
            return False, "Service name contains invalid characters"

        return True, ""

    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """Validate username format - FIXED."""
        if not username or not username.strip():
            return False, "Username cannot be empty"

        if len(username) > Config.MAX_USERNAME_LENGTH:
            return False, f"Username too long (max {Config.MAX_USERNAME_LENGTH})"

        if "\x00" in username:
            return False, "Username contains invalid null byte"

        return True, ""

    @staticmethod
    def validate_password_strength(
        password: str, min_length: int = None
    ) -> Tuple[bool, str]:
        """Validate password strength - FIXED."""
        if min_length is None:
            min_length = Config.MIN_PASSWORD_LENGTH

        if len(password) > InputLimits.MAX_PASSWORD_LENGTH:
            return False, f"Password too long (max {InputLimits.MAX_PASSWORD_LENGTH})"

        if len(password) < min_length:
            return False, f"Password must be at least {min_length} characters"

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)

        if not (has_upper and has_lower and has_digit):
            return False, "Password must contain uppercase, lowercase, and numbers"

        common_passwords = [
            "password",
            "12345678",
            "qwerty",
            "abc123",
            "password1",
            "password123",
            "admin123",
            "welcome123",
        ]
        if password.lower() in common_passwords:
            return False, "Password is too common"

        return True, ""

    @staticmethod
    def validate_recovery_phrase(
        phrase: str, min_words: int = None
    ) -> Tuple[bool, str]:
        """Validate recovery phrase with entropy check."""
        if min_words is None:
            min_words = Config.MIN_RECOVERY_PHRASE_WORDS

        if len(phrase) > InputLimits.MAX_RECOVERY_PHRASE_LENGTH:
            return (
                False,
                f"Recovery phrase too long (max {InputLimits.MAX_RECOVERY_PHRASE_LENGTH})",
            )

        words = phrase.split()
        if len(words) < min_words:
            return False, f"Recovery phrase must have at least {min_words} words"

        # Check word length
        for word in words:
            if len(word) < 3:
                return False, "Recovery phrase words should be at least 3 characters"

        # CHECK ENTROPY
        entropy = InputValidator.calculate_entropy(phrase)
        min_entropy = 60  # Approximately 60 bits of entropy

        if entropy < min_entropy:
            return False, (
                f"Recovery phrase is too predictable. "
                f"Use more varied words and characters."
            )

        # Check for repeated words
        word_counts = Counter(words)
        max_repetitions = max(3, len(words) // 3)  # Allow some repetition

        for word, count in word_counts.items():
            if count > max_repetitions:
                return False, f"Word '{word}' is repeated too many times"

        # Check for sequential patterns
        sequential_patterns = ["123", "abc", "qwerty", "000", "111"]
        phrase_lower = phrase.lower()

        for pattern in sequential_patterns:
            if pattern in phrase_lower:
                return False, f"Avoid sequential patterns like '{pattern}'"

        return True, ""

    @staticmethod
    def validate_notes(notes: str) -> Tuple[bool, str]:
        """Validate notes length - FIXED."""
        if len(notes) > Config.MAX_NOTES_LENGTH:
            return False, f"Notes too long (max {Config.MAX_NOTES_LENGTH})"

        if "\x00" in notes:
            return False, "Notes contain invalid null byte"

        return True, ""
