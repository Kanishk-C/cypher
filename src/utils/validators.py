"""Reusable validation utilities."""

import re
import math
from collections import Counter
from typing import Tuple
from src.config import Config
from src.core.crypto import InputLimits  # Import new limits class


class InputValidator:

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

        # CHECK ENTROPY (NEW)
        entropy = InputValidator.calculate_entropy(phrase)
        min_entropy = 60  # Approximately 60 bits of entropy

        if entropy < min_entropy:
            return False, (
                f"Recovery phrase is too predictable. "
                f"Use more varied words and characters."
            )

        # Check for repeated words (NEW)
        word_counts = Counter(words)
        max_repetitions = len(words) // 3  # Allow some repetition

        for word, count in word_counts.items():
            if count > max_repetitions:
                return False, f"Word '{word}' is repeated too many times"

        # Check for sequential patterns (NEW)
        sequential_patterns = ["123", "abc", "qwerty", "000", "111"]
        phrase_lower = phrase.lower()

        for pattern in sequential_patterns:
            if pattern in phrase_lower:
                return False, f"Avoid sequential patterns like '{pattern}'"

        return True, ""
