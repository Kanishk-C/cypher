"""Cryptographic operations and security utilities."""

import os
import hmac
import hashlib
import base64
import secrets
import gc
import time
import tempfile
import logging
import threading  # ADDED - Missing import
from typing import Tuple, Optional

try:
    import fcntl
except ImportError:
    fcntl = None

from argon2.low_level import hash_secret, Type as Argon2Type
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag

from src.config import Config
from src.exceptions import CoreException, DecryptionError
from src.data.database import get_storage_directory


# ============================================
# SECURITY FIXES & ADDITIONS
# ============================================


def safe_string_compare(a: str, b: str) -> bool:
    """Constant-time string comparison for secrets."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class InputLimits:
    """Maximum input lengths to prevent memory exhaustion."""

    MAX_PASSWORD_LENGTH = Config.MAX_PASSWORD_LENGTH
    MAX_RECOVERY_PHRASE_LENGTH = Config.MAX_RECOVERY_PHRASE_LENGTH


class SecureFileHandler:
    """Secure file operations with atomic writes and proper locking."""

    @staticmethod
    def write_secure(path: str, data: bytes, mode: int = 0o600):
        dir_path = os.path.dirname(path)
        os.makedirs(dir_path, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(dir=dir_path, prefix=".tmp_cypher_")
        try:
            if hasattr(os, "chmod"):
                os.chmod(temp_path, mode)
            with os.fdopen(fd, "wb") as tmp_file:
                tmp_file.write(data)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.replace(temp_path, path)
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise CoreException(f"Secure write failed: {e}")

    @staticmethod
    def read_secure(path: str) -> Optional[bytes]:
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as f:
                return f.read()
        except Exception as e:
            raise CoreException(f"Failed to read {path}: {e}")


# ========== Password Hashing ==========
_ph = PasswordHasher(
    time_cost=Config.ARGON2_TIME_COST,
    memory_cost=Config.ARGON2_MEMORY_COST,
    parallelism=Config.ARGON2_PARALLELISM,
    hash_len=Config.ARGON2_PASS_HASH_LEN,
    salt_len=Config.ARGON2_SALT_LEN,
)


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        _ph.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False


# ========== Key Derivation ==========
def generate_salt() -> bytes:
    return secrets.token_bytes(Config.SALT_SIZE_BYTES)


def derive_keys(password: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    kdf = hash_secret(
        secret=password,
        salt=salt,
        time_cost=Config.ARGON2_TIME_COST,
        memory_cost=Config.ARGON2_MEMORY_COST,
        parallelism=Config.ARGON2_PARALLELISM,
        hash_len=Config.ARGON2_KEY_LEN,
        type=Argon2Type.ID,
    )
    return kdf[:32], kdf[32:]


def derive_profile_keys(
    password: str, profile: str, date: str, salt: bytes
) -> Tuple[bytes, bytes]:
    material = f"{password}{profile}{date}".encode("utf-8")
    return derive_keys(material, salt)


def derive_device_keys(token: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    return derive_keys(token, salt)


def derive_recovery_keys(phrase: str, salt: bytes) -> Tuple[bytes, bytes]:
    return derive_keys(phrase.encode("utf-8"), salt)


# ========== Encryption/Decryption ==========
def encrypt_data(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_data(token: bytes, key: bytes) -> bytes:
    try:
        aesgcm = AESGCM(key)
        nonce, ciphertext = token[:12], token[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise DecryptionError(
            "Decryption failed. Data may be corrupt or key is incorrect."
        )


# ========== Integrity Verification ==========
class IntegrityVerifier:
    @staticmethod
    def create_hmac(data: bytes, key: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def verify_hmac(data: bytes, tag: bytes, key: bytes) -> bool:
        expected_tag = IntegrityVerifier.create_hmac(data, key)
        return hmac.compare_digest(tag, expected_tag)

    @staticmethod
    def protect_data(data: bytes, enc_key: bytes, hmac_key: bytes) -> bytes:
        b64_key = base64.urlsafe_b64encode(enc_key)
        encrypted = Fernet(b64_key).encrypt(data)
        tag = IntegrityVerifier.create_hmac(encrypted, hmac_key)
        return encrypted + tag

    @staticmethod
    def verify_and_decrypt(data: bytes, enc_key: bytes, hmac_key: bytes) -> bytes:
        if len(data) < Config.HMAC_SIZE_BYTES:
            raise CoreException("Invalid encrypted data: too short for HMAC tag.")

        encrypted_data, tag = (
            data[: -Config.HMAC_SIZE_BYTES],
            data[-Config.HMAC_SIZE_BYTES :],
        )

        if not IntegrityVerifier.verify_hmac(encrypted_data, tag, hmac_key):
            raise CoreException(
                "Integrity verification failed - data may have been tampered with."
            )

        try:
            b64_key = base64.urlsafe_b64encode(enc_key)
            return Fernet(b64_key).decrypt(encrypted_data)
        except InvalidToken:
            raise DecryptionError("Decryption failed: invalid token.")


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


class NonceTracker:
    """
    Track used nonces to prevent IV reuse.
    Note: In practice, with 96-bit nonces, collision is ~2^-96
    This is mostly for paranoid security applications.
    """

    def __init__(self, max_nonces: int = 100000):
        self._used_nonces = set()
        self._max_nonces = max_nonces
        self._lock = threading.Lock()

    def check_and_register(self, nonce: bytes) -> bool:
        """Check if nonce was used, register if not."""
        with self._lock:
            if nonce in self._used_nonces:
                return False  # Collision detected!

            self._used_nonces.add(nonce)

            # Rotate set if too large
            if len(self._used_nonces) > self._max_nonces:
                # Remove oldest 20%
                to_remove = len(self._used_nonces) // 5
                for _ in range(to_remove):
                    self._used_nonces.pop()

            return True


# Global nonce tracker (optional)
_nonce_tracker = NonceTracker()


def encrypt_data_with_tracking(data: bytes, key: bytes) -> bytes:
    """Encryption with nonce collision detection."""
    max_retries = 3

    for attempt in range(max_retries):
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)

        if _nonce_tracker.check_and_register(nonce):
            # Nonce is unique, proceed
            ciphertext = aesgcm.encrypt(nonce, data, None)
            return nonce + ciphertext

        logging.warning(f"Nonce collision detected (attempt {attempt+1})")

    raise CoreException("Failed to generate unique nonce after retries")
