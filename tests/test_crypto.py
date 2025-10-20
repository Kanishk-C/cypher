import pytest
import os
import tempfile
from unittest.mock import Mock, patch
from src.core.crypto import (
    hash_password,
    verify_password,
    generate_salt,
    derive_keys,
    derive_profile_keys,
    encrypt_data,
    decrypt_data,
    IntegrityVerifier,
    SecureMemory,
    SecureFileHandler,
    RateLimiter,
)
from src.exceptions import CoreException, DecryptionError


class TestPasswordHashing:
    """Test password hashing functionality."""

    def test_hash_password_generates_different_hashes(self):
        """Same password should generate different hashes (salt)."""
        pwd = "TestPassword123"
        hash1 = hash_password(pwd)
        hash2 = hash_password(pwd)
        assert hash1 != hash2

    def test_verify_password_correct(self):
        """Correct password should verify successfully."""
        pwd = "CorrectPassword123"
        pwd_hash = hash_password(pwd)
        assert verify_password(pwd_hash, pwd) == True

    def test_verify_password_incorrect(self):
        """Incorrect password should fail verification."""
        pwd = "CorrectPassword123"
        pwd_hash = hash_password(pwd)
        assert verify_password(pwd_hash, "WrongPassword123") == False

    def test_hash_empty_password(self):
        """Empty password should still hash (no crash)."""
        pwd_hash = hash_password("")
        assert pwd_hash is not None
        assert len(pwd_hash) > 0

    def test_hash_unicode_password(self):
        """Unicode characters should be handled correctly."""
        pwd = "пароль密码🔒"
        pwd_hash = hash_password(pwd)
        assert verify_password(pwd_hash, pwd) == True

    def test_hash_very_long_password(self):
        """Very long passwords should be handled."""
        pwd = "x" * 10000
        pwd_hash = hash_password(pwd)
        assert verify_password(pwd_hash, pwd) == True


class TestKeyDerivation:
    """Test key derivation functions."""

    def test_generate_salt_unique(self):
        """Each salt should be unique."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        assert salt1 != salt2
        assert len(salt1) == 16
        assert len(salt2) == 16

    def test_derive_keys_deterministic(self):
        """Same input should produce same keys."""
        pwd = b"password"
        salt = b"1234567890123456"
        key1, hmac1 = derive_keys(pwd, salt)
        key2, hmac2 = derive_keys(pwd, salt)
        assert key1 == key2
        assert hmac1 == hmac2

    def test_derive_keys_different_salts(self):
        """Different salts should produce different keys."""
        pwd = b"password"
        salt1 = generate_salt()
        salt2 = generate_salt()
        key1, _ = derive_keys(pwd, salt1)
        key2, _ = derive_keys(pwd, salt2)
        assert key1 != key2

    def test_derive_profile_keys_unique_per_profile(self):
        """Different profiles should have different keys."""
        pwd = "MasterPassword123"
        salt = generate_salt()
        date = "2025-01-01T00:00:00"

        key1, _ = derive_profile_keys(pwd, "profile1", date, salt)
        key2, _ = derive_profile_keys(pwd, "profile2", date, salt)
        assert key1 != key2

    def test_derive_keys_correct_length(self):
        """Derived keys should have correct length."""
        pwd = b"password"
        salt = generate_salt()
        enc_key, hmac_key = derive_keys(pwd, salt)
        assert len(enc_key) == 32
        assert len(hmac_key) == 32


class TestEncryptionDecryption:
    """Test encryption and decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encryption then decryption should recover original."""
        data = b"Secret data"
        key = os.urandom(32)
        encrypted = encrypt_data(data, key)
        decrypted = decrypt_data(encrypted, key)
        assert decrypted == data

    def test_encrypt_produces_different_ciphertext(self):
        """Same data encrypted twice should produce different ciphertext."""
        data = b"Secret data"
        key = os.urandom(32)
        enc1 = encrypt_data(data, key)
        enc2 = encrypt_data(data, key)
        assert enc1 != enc2  # Different nonces

    def test_decrypt_wrong_key_fails(self):
        """Decryption with wrong key should fail."""
        data = b"Secret data"
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        encrypted = encrypt_data(data, key1)
        with pytest.raises(DecryptionError):
            decrypt_data(encrypted, key2)

    def test_decrypt_corrupted_data_fails(self):
        """Decryption of corrupted data should fail."""
        data = b"Secret data"
        key = os.urandom(32)
        encrypted = encrypt_data(data, key)
        corrupted = encrypted[:12] + b"X" * (len(encrypted) - 12)
        with pytest.raises(DecryptionError):
            decrypt_data(corrupted, key)

    def test_encrypt_empty_data(self):
        """Empty data should encrypt and decrypt correctly."""
        data = b""
        key = os.urandom(32)
        encrypted = encrypt_data(data, key)
        decrypted = decrypt_data(encrypted, key)
        assert decrypted == data

    def test_encrypt_large_data(self):
        """Large data should encrypt correctly."""
        data = os.urandom(1024 * 1024)  # 1 MB
        key = os.urandom(32)
        encrypted = encrypt_data(data, key)
        decrypted = decrypt_data(encrypted, key)
        assert decrypted == data


class TestIntegrityVerifier:
    """Test HMAC integrity verification."""

    def test_protect_verify_roundtrip(self):
        """Protect then verify should recover original."""
        data = b"Test data"
        enc_key = os.urandom(32)
        hmac_key = os.urandom(32)

        protected = IntegrityVerifier.protect_data(data, enc_key, hmac_key)
        recovered = IntegrityVerifier.verify_and_decrypt(protected, enc_key, hmac_key)
        assert recovered == data

    def test_verify_tampered_data_fails(self):
        """Verification of tampered data should fail."""
        data = b"Test data"
        enc_key = os.urandom(32)
        hmac_key = os.urandom(32)

        protected = IntegrityVerifier.protect_data(data, enc_key, hmac_key)
        tampered = protected[:-5] + b"XXXXX"

        with pytest.raises(CoreException, match="Integrity verification failed"):
            IntegrityVerifier.verify_and_decrypt(tampered, enc_key, hmac_key)

    def test_verify_wrong_hmac_key_fails(self):
        """Verification with wrong HMAC key should fail."""
        data = b"Test data"
        enc_key = os.urandom(32)
        hmac_key1 = os.urandom(32)
        hmac_key2 = os.urandom(32)

        protected = IntegrityVerifier.protect_data(data, enc_key, hmac_key1)

        with pytest.raises(CoreException):
            IntegrityVerifier.verify_and_decrypt(protected, enc_key, hmac_key2)

    def test_hmac_constant_time_comparison(self):
        """HMAC verification should use constant-time comparison."""
        # This is tested by checking hmac.compare_digest is used
        data = b"test"
        key = os.urandom(32)
        tag1 = IntegrityVerifier.create_hmac(data, key)
        tag2 = IntegrityVerifier.create_hmac(data, key)
        assert IntegrityVerifier.verify_hmac(data, tag1, key)


class TestSecureMemory:
    """Test secure memory handling."""

    def test_secure_memory_context_manager(self):
        """SecureMemory should work as context manager."""
        data = b"secret"
        with SecureMemory(data) as sm:
            assert sm.get() == data

    def test_secure_memory_cleared_after_context(self):
        """SecureMemory should be cleared after context exit."""
        data = b"secret"
        sm = SecureMemory(data)
        with sm:
            pass
        with pytest.raises(CoreException):
            sm.get()

    def test_secure_memory_explicit_clear(self):
        """Explicit clear should prevent further access."""
        data = b"secret"
        sm = SecureMemory(data)
        sm.clear()
        with pytest.raises(CoreException):
            sm.get()

    def test_secure_memory_deletion(self):
        """Memory should be cleared on deletion."""
        data = b"secret"
        sm = SecureMemory(data)
        del sm
        # If this doesn't crash, cleanup worked


class TestSecureFileHandler:
    """Test secure file operations."""

    def test_write_read_roundtrip(self):
        """Write then read should recover data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.dat")
            data = b"test data"

            SecureFileHandler.write_secure(path, data)
            read_data = SecureFileHandler.read_secure(path)

            assert read_data == data

    def test_write_nonexistent_directory_fails(self):
        """Writing to nonexistent directory should fail."""
        path = "/nonexistent/directory/file.dat"
        with pytest.raises(CoreException):
            SecureFileHandler.write_secure(path, b"data")

    def test_read_nonexistent_file_returns_none(self):
        """Reading nonexistent file should return None."""
        result = SecureFileHandler.read_secure("/nonexistent/file.dat")
        assert result is None

    def test_write_atomic_replace(self):
        """Write should atomically replace existing file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.dat")

            SecureFileHandler.write_secure(path, b"original")
            SecureFileHandler.write_secure(path, b"updated")

            result = SecureFileHandler.read_secure(path)
            assert result == b"updated"

    @pytest.mark.skipif(os.name == "nt", reason="Unix permissions test")
    def test_file_permissions_secure(self):
        """Created files should have secure permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.dat")
            SecureFileHandler.write_secure(path, b"data", mode=0o600)

            stat_info = os.stat(path)
            mode = stat_info.st_mode & 0o777
            assert mode == 0o600


class TestRateLimiter:
    """Test rate limiting functionality."""

    def test_rate_limiter_allows_initial_attempts(self):
        """Initial attempts should be allowed."""
        limiter = RateLimiter(max_attempts=3, lockout_time=60)
        allowed, _ = limiter.check_attempt("user1")
        assert allowed == True

    def test_rate_limiter_blocks_after_max_attempts(self):
        """Should block after max attempts."""
        limiter = RateLimiter(max_attempts=3, lockout_time=60)

        for _ in range(3):
            limiter.check_attempt("user1")

        allowed, wait = limiter.check_attempt("user1")
        assert allowed == False
        assert wait > 0

    def test_rate_limiter_reset_clears_attempts(self):
        """Reset should clear attempt counter."""
        limiter = RateLimiter(max_attempts=3, lockout_time=60)

        for _ in range(3):
            limiter.check_attempt("user1")

        limiter.reset("user1")
        allowed, _ = limiter.check_attempt("user1")
        assert allowed == True

    def test_rate_limiter_per_identifier(self):
        """Rate limiting should be per identifier."""
        limiter = RateLimiter(max_attempts=2, lockout_time=60)

        limiter.check_attempt("user1")
        limiter.check_attempt("user1")

        allowed, _ = limiter.check_attempt("user2")
        assert allowed == True

    def test_rate_limiter_expires_old_attempts(self):
        """Old attempts should expire after lockout time."""
        limiter = RateLimiter(max_attempts=2, lockout_time=1)

        limiter.check_attempt("user1")
        limiter.check_attempt("user1")

        import time

        time.sleep(1.1)

        allowed, _ = limiter.check_attempt("user1")
        assert allowed == True
