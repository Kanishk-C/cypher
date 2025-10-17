"""Reusable validation utilities."""

import re
from typing import Tuple
from config import Config


class InputValidator:
    """Centralized input validation."""
    
    @staticmethod
    def validate_service_name(service: str) -> Tuple[bool, str]:
        """Validate service name format."""
        if not service or not service.strip():
            return False, "Service name cannot be empty"
        if len(service) > Config.MAX_SERVICE_NAME_LENGTH:
            return False, f"Service name too long (max {Config.MAX_SERVICE_NAME_LENGTH} characters)"
        if not re.match(r'^[a-zA-Z0-9\s\-_.@]+$', service):
            return False, "Service name contains invalid characters"
        return True, ""
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """Validate username format."""
        if not username or not username.strip():
            return False, "Username cannot be empty"
        if len(username) > Config.MAX_USERNAME_LENGTH:
            return False, f"Username too long (max {Config.MAX_USERNAME_LENGTH} characters)"
        return True, ""
    
    @staticmethod
    def validate_password_strength(password: str, min_length: int = None) -> Tuple[bool, str]:
        """Validate password meets security requirements."""
        if min_length is None:
            min_length = Config.MIN_PASSWORD_LENGTH
            
        if len(password) < min_length:
            return False, f"Password must be at least {min_length} characters"
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        
        if not (has_upper and has_lower and has_digit):
            return False, "Password must contain uppercase, lowercase, and numbers"
        
        # Check against common passwords
        common_passwords = ['password', '12345678', 'qwerty', 'abc123', 'password1', 
                           'password123', 'admin123', 'welcome123']
        if password.lower() in common_passwords:
            return False, "Password is too common"
        
        return True, ""
    
    @staticmethod
    def validate_recovery_phrase(phrase: str, min_words: int = None) -> Tuple[bool, str]:
        """Validate recovery phrase format."""
        if min_words is None:
            min_words = Config.MIN_RECOVERY_PHRASE_WORDS
            
        words = phrase.split()
        if len(words) < min_words:
            return False, f"Recovery phrase must have at least {min_words} words"
        
        # Check for reasonable word length
        for word in words:
            if len(word) < 3:
                return False, "Recovery phrase words should be at least 3 characters"
        
        return True, ""
    
    @staticmethod
    def validate_notes(notes: str) -> Tuple[bool, str]:
        """Validate notes length."""
        if len(notes) > Config.MAX_NOTES_LENGTH:
            return False, f"Notes too long (max {Config.MAX_NOTES_LENGTH} characters)"
        return True, ""
