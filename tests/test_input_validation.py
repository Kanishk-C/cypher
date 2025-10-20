import pytest
from src.utils.validators import InputValidator


class TestInputSanitization:
    """Test all input validation and sanitization."""

    def test_service_name_xss_prevention(self):
        """Service names should not allow XSS."""
        dangerous_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror='alert(1)'>",
        ]

        for dangerous in dangerous_inputs:
            valid, _ = InputValidator.validate_service_name(dangerous)
            assert valid == False

    def test_null_byte_injection(self):
        """Null bytes should be rejected."""
        inputs_with_null = [
            "test\x00.txt",
            "service\x00name",
        ]

        for dangerous in inputs_with_null:
            valid, _ = InputValidator.validate_service_name(dangerous)
            assert valid == False

    def test_unicode_handling(self):
        """Unicode characters should be handled safely."""
        unicode_inputs = ["测试服务", "テスト", "مرحبا", "😀🔒"]

        # Should either accept or reject consistently
        for text in unicode_inputs:
            valid, msg = InputValidator.validate_service_name(text)
            # Current implementation rejects these (only allows alphanumeric)
            assert valid == False

    def test_very_long_input_rejection(self):
        """Very long inputs should be rejected."""
        long_input = "a" * 10000
        valid, msg = InputValidator.validate_service_name(long_input)
        assert valid == False
        assert "long" in msg.lower()
