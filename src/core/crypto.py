"""Cryptographic operations and security utilities."""

import os
import hmac
import hashlib
import base64
import secrets
import gc
import time
from typing import Tuple, Optional
from argon2.low_level import hash_secret, Type as Argon2Type
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag
from src.config import Config
from src.exceptions import CoreException, DecryptionError

# ========== Password Hashing ==========
_ph = PasswordHasher(
    time_cost=Config.ARGON2_TIME_COST,
    memory_cost=Config.ARGON2_MEMORY_COST,
    parallelism=Config.ARGON2_PARALLELISM,
    hash_len=Config.ARGON2_PASS_HASH_LEN,
    salt_len=Config.ARGON2_SALT_LEN,
)


def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify password against hash."""
    try:
        _ph.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False


# ========== Key Derivation ==========
def generate_salt() -> bytes:
    """Generate random salt."""
    return os.urandom(Config.SALT_SIZE_BYTES)


def derive_keys(password: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    """Derive encryption and HMAC keys using Argon2id."""
    kdf = hash_secret(
        secret=password,
        salt=salt,
        time_cost=Config.ARGON2_TIME_COST,
        memory_cost=Config.ARGON2_MEMORY_COST,
        parallelism=Config.ARGON2_PARALLELISM,
        hash_len=Config.ARGON2_KEY_LEN,
        type=Argon2Type.ID,
    )
    return kdf[:32], kdf[32:]  # enc_key, hmac_key


def derive_profile_keys(
    password: str, profile: str, date: str, salt: bytes
) -> Tuple[bytes, bytes]:
    """Derive profile-specific keys."""
    material = f"{password}{profile}{date}".encode("utf-8")
    return derive_keys(material, salt)


def derive_device_keys(token: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    """Derive keys from device token."""
    return derive_keys(token, salt)


def derive_recovery_keys(phrase: str, salt: bytes) -> Tuple[bytes, bytes]:
    """Derive keys from recovery phrase."""
    return derive_keys(phrase.encode("utf-8"), salt)


# ========== Encryption/Decryption ==========
def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypt using AES-256-GCM."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_data(token: bytes, key: bytes) -> bytes:
    """Decrypt data."""
    try:
        aesgcm = AESGCM(key)
        nonce = token[:12]
        ciphertext = token[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise DecryptionError(
            "Decryption failed. Data may be corrupt or key is incorrect."
        )


# ========== Integrity Verification ==========
class IntegrityVerifier:
    """HMAC-based integrity verification."""

    @staticmethod
    def create_hmac(data: bytes, key: bytes) -> bytes:
        """Create HMAC-SHA256 tag."""
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def verify_hmac(data: bytes, tag: bytes, key: bytes) -> bool:
        """Verify HMAC tag."""
        expected = IntegrityVerifier.create_hmac(data, key)
        return hmac.compare_digest(tag, expected)

    @staticmethod
    def protect_data(data: bytes, enc_key: bytes, hmac_key: bytes) -> bytes:
        """Encrypt data and append HMAC (Encrypt-then-MAC)."""
        b64_key = base64.urlsafe_b64encode(enc_key)
        encrypted = Fernet(b64_key).encrypt(data)
        tag = IntegrityVerifier.create_hmac(encrypted, hmac_key)
        return encrypted + tag

    @staticmethod
    def verify_and_decrypt(data: bytes, enc_key: bytes, hmac_key: bytes) -> bytes:
        """Verify HMAC and decrypt."""
        if len(data) < Config.HMAC_SIZE_BYTES:
            raise CoreException("Invalid encrypted data")

        encrypted = data[: -Config.HMAC_SIZE_BYTES]
        tag = data[-Config.HMAC_SIZE_BYTES :]

        if not IntegrityVerifier.verify_hmac(encrypted, tag, hmac_key):
            raise CoreException("Integrity verification failed")

        try:
            b64_key = base64.urlsafe_b64encode(enc_key)
            return Fernet(b64_key).decrypt(encrypted)
        except InvalidToken:
            raise CoreException("Decryption failed")


# ========== Secure Memory ==========
class SecureMemory:
    """Wrapper for sensitive data that clears on deletion."""

    def __init__(self, data: bytes):
        self._data = bytearray(data)
        self._cleared = False

    def get(self) -> bytes:
        if self._cleared:
            raise CoreException("Accessing cleared secure memory")
        return bytes(self._data)

    def clear(self):
        if not self._cleared and hasattr(self, "_data"):
            for _ in range(3):
                for i in range(len(self._data)):
                    self._data[i] = secrets.randbits(8)
            self._data.clear()
            self._cleared = True
            gc.collect()

    def __del__(self):
        self.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()


# ========== Secure File Handler ==========
class SecureFileHandler:
    """Secure file operations."""

    @staticmethod
    def write_secure(path: str, data: bytes, mode: int = 0o600):
        """Write file with secure permissions."""
        temp_path = path + ".tmp"
        try:
            with open(temp_path, "wb") as f:
                f.write(data)

            if hasattr(os, "chmod"):
                os.chmod(temp_path, mode)

            if os.path.exists(path):
                os.replace(temp_path, path)
            else:
                os.rename(temp_path, path)
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
            raise CoreException(f"Secure write failed: {e}")

    @staticmethod
    def read_secure(path: str) -> Optional[bytes]:
        """Read file securely."""
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as f:
                return f.read()
        except Exception as e:
            raise CoreException(f"Failed to read {path}: {e}")


# ========== Rate Limiter ==========
class RateLimiter:
    """Rate limiting for login attempts."""

    def __init__(
        self,
        max_attempts: int = Config.MAX_LOGIN_ATTEMPTS,
        lockout_time: int = Config.LOCKOUT_TIME_SECONDS,
    ):
        self.max_attempts = max_attempts
        self.lockout_time = lockout_time
        self.attempts = {}

    def check_attempt(self, identifier: str) -> Tuple[bool, int]:
        """Check if attempt is allowed. Returns (allowed, wait_seconds)."""
        now = time.time()

        if identifier not in self.attempts:
            self.attempts[identifier] = []

        self.attempts[identifier] = [
            t for t in self.attempts[identifier] if now - t < self.lockout_time
        ]

        if len(self.attempts[identifier]) >= self.max_attempts:
            oldest = min(self.attempts[identifier])
            wait_time = int(self.lockout_time - (now - oldest))
            return False, max(0, wait_time)

        self.attempts[identifier].append(now)
        return True, 0

    def reset(self, identifier: str):
        """Reset attempts after successful login."""
        if identifier in self.attempts:
            del self.attempts[identifier]
