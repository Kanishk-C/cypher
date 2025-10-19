from src.utils.validators import InputValidator


class TestServiceNameValidation:
    """Test service name validation."""

    def test_valid_service_names(self):
        """Valid service names should pass."""
        valid_names = [
            "github",
            "my-service",
            "service_123",
            "test.com",
            "email@domain",
        ]
        for name in valid_names:
            valid, msg = InputValidator.validate_service_name(name)
            assert valid == True, f"{name} should be valid"

    def test_empty_service_name_invalid(self):
        """Empty service name should be invalid."""
        valid, msg = InputValidator.validate_service_name("")
        assert valid == False
        assert "empty" in msg.lower()

    def test_long_service_name_invalid(self):
        """Too long service name should be invalid."""
        long_name = "x" * 200
        valid, msg = InputValidator.validate_service_name(long_name)
        assert valid == False
        assert "long" in msg.lower()

    def test_invalid_characters(self):
        """Service names with invalid characters should fail."""
        invalid_names = [
            "service/path",
            "service\\path",
            "service<script>",
            "service;drop",
        ]
        for name in invalid_names:
            valid, msg = InputValidator.validate_service_name(name)
            assert valid == False, f"{name} should be invalid"


class TestPasswordStrengthValidation:
    """Test password strength validation."""

    def test_strong_passwords_valid(self):
        """Strong passwords should pass."""
        strong_passwords = ["MyP@ssw0rd", "SecurePass123", "Complex1tyRules"]
        for pwd in strong_passwords:
            valid, msg = InputValidator.validate_password_strength(pwd)
            assert valid == True

    def test_short_password_invalid(self):
        """Short passwords should be invalid."""
        valid, msg = InputValidator.validate_password_strength("Pass1")
        assert valid == False
        assert "8 characters" in msg

    def test_no_uppercase_invalid(self):
        """Password without uppercase should be invalid."""
        valid, msg = InputValidator.validate_password_strength("password123")
        assert valid == False

    def test_no_lowercase_invalid(self):
        """Password without lowercase should be invalid."""
        valid, msg = InputValidator.validate_password_strength("PASSWORD123")
        assert valid == False

    def test_no_digit_invalid(self):
        """Password without digit should be invalid."""
        valid, msg = InputValidator.validate_password_strength("PasswordOnly")
        assert valid == False

    def test_common_password_invalid(self):
        """Common passwords should be rejected."""
        valid, msg = InputValidator.validate_password_strength("password123")
        assert valid == False
        assert "common" in msg.lower()
