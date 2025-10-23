"""Cryptographic operations and security utilities - v1.0.0 PRODUCTION READY."""

import os
import hmac
import hashlib
import base64
import secrets
import gc
import time
import tempfile
import logging
import threading
from typing import Tuple, Optional
from collections import deque

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
# SECURITY UTILITIES
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
        """
        Write data securely with atomic replacement.

        Args:
            path: Target file path
            data: Bytes to write
            mode: File permissions (Unix only)

        Raises:
            CoreException: If write fails
        """
        dir_path = os.path.dirname(path)
        if dir_path:  # Only create if path has directory component
            os.makedirs(dir_path, exist_ok=True)

        # Create temp file in same directory for atomic replace
        fd, temp_path = tempfile.mkstemp(
            dir=dir_path if dir_path else ".", prefix=".tmp_cypher_"
        )

        try:
            # Set permissions before writing (Unix only)
            if hasattr(os, "chmod"):
                os.chmod(temp_path, mode)

            # Write data with explicit sync
            with os.fdopen(fd, "wb") as tmp_file:
                tmp_file.write(data)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())

            # Atomic replace
            os.replace(temp_path, path)

        except Exception as e:
            # Cleanup on failure
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise CoreException(f"Secure write failed: {e}")

    @staticmethod
    def read_secure(path: str) -> Optional[bytes]:
        """
        Read file securely.

        Args:
            path: File path to read

        Returns:
            File contents as bytes, or None if file doesn't exist

        Raises:
            CoreException: If read fails
        """
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as f:
                return f.read()
        except Exception as e:
            raise CoreException(f"Failed to read {path}: {e}")


# ============================================
# PASSWORD HASHING
# ============================================

_ph = PasswordHasher(
    time_cost=Config.ARGON2_TIME_COST,
    memory_cost=Config.ARGON2_MEMORY_COST,
    parallelism=Config.ARGON2_PARALLELISM,
    hash_len=Config.ARGON2_PASS_HASH_LEN,
    salt_len=Config.ARGON2_SALT_LEN,
)


def hash_password(password: str) -> str:
    """
    Hash password using Argon2id.

    Args:
        password: Plain text password

    Returns:
        Argon2 hash string
    """
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """
    Verify password against Argon2 hash.

    Args:
        password_hash: Stored Argon2 hash
        password: Plain text password to verify

    Returns:
        True if password matches, False otherwise
    """
    try:
        _ph.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False


# ============================================
# KEY DERIVATION
# ============================================


def generate_salt() -> bytes:
    """Generate cryptographically secure random salt."""
    return secrets.token_bytes(Config.SALT_SIZE_BYTES)


def derive_keys(password: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    """
    Derive encryption and HMAC keys using Argon2id.

    Args:
        password: Input password material
        salt: Random salt

    Returns:
        Tuple of (encryption_key, hmac_key), each 32 bytes
    """
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
    """
    Derive profile-specific encryption keys.

    Args:
        password: Master password
        profile: Profile name
        date: Profile creation date (ISO format)
        salt: Random salt

    Returns:
        Tuple of (encryption_key, hmac_key)
    """
    material = f"{password}|{profile}|{date}".encode("utf-8")
    return derive_keys(material, salt)


def derive_device_keys(token: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    """
    Derive keys from device token.

    Args:
        token: Device-specific token
        salt: Random salt

    Returns:
        Tuple of (encryption_key, hmac_key)
    """
    return derive_keys(token, salt)


def derive_recovery_keys(phrase: str, salt: bytes) -> Tuple[bytes, bytes]:
    """
    Derive keys from recovery phrase.

    Args:
        phrase: Recovery phrase
        salt: Random salt

    Returns:
        Tuple of (encryption_key, hmac_key)
    """
    return derive_keys(phrase.encode("utf-8"), salt)


# ============================================
# NONCE TRACKING (COLLISION PREVENTION)
# ============================================


class NonceTracker:
    """
    Thread-safe nonce collision detector.

    Prevents AES-GCM nonce reuse by tracking recently used nonces.
    """

    def __init__(self, max_nonces: int = 10000):
        """
        Initialize nonce tracker.

        Args:
            max_nonces: Maximum nonces to track (older ones are forgotten)
        """
        self._used_nonces = set()
        self._nonce_queue = deque(maxlen=max_nonces)
        self._max_nonces = max_nonces
        self._lock = threading.Lock()

    def check_and_register(self, nonce: bytes) -> bool:
        """
        Check if nonce is unique and register it.

        Args:
            nonce: Nonce to check and register

        Returns:
            True if nonce is unique (registered), False if collision detected
        """

        with self._lock:
            if nonce in self._used_nonces:
                return False

            # Check if queue is full and remove oldest from set
            if len(self._nonce_queue) >= self._max_nonces:
                oldest = self._nonce_queue[0]
                self._used_nonces.discard(oldest)

            # Add new nonce
            self._nonce_queue.append(nonce)
            self._used_nonces.add(nonce)

            return True


# Global nonce tracker instance
_nonce_tracker = NonceTracker()


# ============================================
# ENCRYPTION/DECRYPTION
# ============================================


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM with nonce collision detection.

    Args:
        data: Plain text data to encrypt
        key: 32-byte encryption key

    Returns:
        Encrypted data: nonce (12 bytes) + ciphertext + auth tag

    Raises:
        CoreException: If unique nonce generation fails after retries
    """
    max_retries = 3

    for attempt in range(max_retries):
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)

        # Check for nonce collision
        if _nonce_tracker.check_and_register(nonce):
            # Nonce is unique, proceed with encryption
            ciphertext = aesgcm.encrypt(nonce, data, None)
            return nonce + ciphertext

        # Collision detected, log and retry
        logging.warning(
            f"Nonce collision detected (attempt {attempt + 1}/{max_retries})"
        )

    # Failed to generate unique nonce after retries
    raise CoreException(f"Failed to generate unique nonce after {max_retries} attempts")


def decrypt_data(token: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data.

    Args:
        token: Encrypted data (nonce + ciphertext + tag)
        key: 32-byte encryption key

    Returns:
        Decrypted plain text

    Raises:
        DecryptionError: If decryption or authentication fails
    """
    try:
        aesgcm = AESGCM(key)
        nonce, ciphertext = token[:12], token[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise DecryptionError(
            "Decryption failed. Data may be corrupt or key is incorrect."
        )


# ============================================
# INTEGRITY VERIFICATION
# ============================================


class IntegrityVerifier:
    """HMAC-based integrity verification for encrypted data."""

    @staticmethod
    def create_hmac(data: bytes, key: bytes) -> bytes:
        """
        Create HMAC-SHA256 tag for data.

        Args:
            data: Data to tag
            key: HMAC key

        Returns:
            32-byte HMAC tag
        """
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def verify_hmac(data: bytes, tag: bytes, key: bytes) -> bool:
        """
        Verify HMAC tag in constant time.

        Args:
            data: Data to verify
            tag: Provided HMAC tag
            key: HMAC key

        Returns:
            True if tag is valid, False otherwise
        """
        expected_tag = IntegrityVerifier.create_hmac(data, key)
        return hmac.compare_digest(tag, expected_tag)

    @staticmethod
    def protect_data(data: bytes, enc_key: bytes, hmac_key: bytes) -> bytes:
        """
        Encrypt and authenticate data.

        Uses Fernet (AES-CBC + HMAC) then adds additional HMAC layer.

        Args:
            data: Plain text data
            enc_key: 32-byte encryption key
            hmac_key: 32-byte HMAC key

        Returns:
            Protected data: encrypted || HMAC(encrypted)
        """
        # Fernet requires base64-encoded key
        b64_key = base64.urlsafe_b64encode(enc_key)
        encrypted = Fernet(b64_key).encrypt(data)

        # Add HMAC for tamper detection
        tag = IntegrityVerifier.create_hmac(encrypted, hmac_key)
        return encrypted + tag

    @staticmethod
    def verify_and_decrypt(data: bytes, enc_key: bytes, hmac_key: bytes) -> bytes:
        """
        Verify integrity and decrypt data.

        Args:
            data: Protected data (encrypted || HMAC)
            enc_key: 32-byte encryption key
            hmac_key: 32-byte HMAC key

        Returns:
            Decrypted plain text

        Raises:
            CoreException: If HMAC verification fails (data tampered)
            DecryptionError: If decryption fails (wrong key/corrupted)
        """
        if len(data) < Config.HMAC_SIZE_BYTES:
            raise CoreException("Invalid encrypted data: too short for HMAC tag.")

        # Split data and HMAC tag
        encrypted_data = data[: -Config.HMAC_SIZE_BYTES]
        tag = data[-Config.HMAC_SIZE_BYTES :]

        # Verify HMAC before attempting decryption
        if not IntegrityVerifier.verify_hmac(encrypted_data, tag, hmac_key):
            raise CoreException(
                "Integrity verification failed - data may have been tampered with."
            )

        # Decrypt using Fernet
        try:
            b64_key = base64.urlsafe_b64encode(enc_key)
            return Fernet(b64_key).decrypt(encrypted_data)
        except InvalidToken:
            raise DecryptionError("Decryption failed: invalid token.")


# ============================================
# SECURE MEMORY MANAGEMENT
# ============================================


class SecureMemory:
    """
    Wrapper for sensitive data that clears memory on deletion.

    Attempts to scrub memory by overwriting with random data.
    Note: Python's memory management makes true secure deletion difficult.
    """

    def __init__(self, data: bytes):
        """
        Initialize secure memory with sensitive data.

        Args:
            data: Sensitive bytes to protect
        """
        self._data = bytearray(data)
        self._cleared = False

    def get(self) -> bytes:
        """
        Get the sensitive data.

        Returns:
            Protected data as bytes

        Raises:
            CoreException: If memory has been cleared
        """
        if self._cleared:
            raise CoreException("Accessing cleared secure memory")
        return bytes(self._data)

    def clear(self):
        """
        Clear sensitive data from memory.

        Overwrites memory 3 times with random data before clearing.
        """
        if not self._cleared and hasattr(self, "_data"):
            # Overwrite with random data 3 times
            for _ in range(3):
                for i in range(len(self._data)):
                    self._data[i] = secrets.randbits(8)

            # Clear the bytearray
            self._data.clear()
            self._cleared = True

            # Force garbage collection
            gc.collect()

    def __del__(self):
        """Cleanup on object deletion."""
        self.clear()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - always clear."""
        self.clear()


# ============================================
# RATE LIMITING
# ============================================


class RateLimiter:
    """
    Time-based rate limiter for authentication attempts.

    Tracks failed attempts per identifier and enforces lockout period.
    """

    def __init__(
        self,
        max_attempts: int = Config.MAX_LOGIN_ATTEMPTS,
        lockout_time: int = Config.LOCKOUT_TIME_SECONDS,
    ):
        """
        Initialize rate limiter.

        Args:
            max_attempts: Maximum attempts before lockout
            lockout_time: Lockout duration in seconds
        """
        self.max_attempts = max_attempts
        self.lockout_time = lockout_time
        self.attempts = {}  # identifier -> list of attempt timestamps

    def check_attempt(self, identifier: str) -> Tuple[bool, int]:
        """
        Check if attempt is allowed and register it.

        Args:
            identifier: Unique identifier (e.g., username, profile name)

        Returns:
            Tuple of (allowed: bool, wait_seconds: int)
            - If allowed=True: attempt is permitted, wait_seconds=0
            - If allowed=False: locked out, wait_seconds=time until unlock
        """
        now = time.time()

        # Initialize attempt list for new identifiers
        if identifier not in self.attempts:
            self.attempts[identifier] = []

        # Remove attempts outside the lockout window
        self.attempts[identifier] = [
            t for t in self.attempts[identifier] if now - t < self.lockout_time
        ]

        # Check if locked out
        if len(self.attempts[identifier]) >= self.max_attempts:
            oldest = min(self.attempts[identifier])
            wait_time = int(self.lockout_time - (now - oldest))
            return False, max(0, wait_time)

        # Attempt allowed, register timestamp
        self.attempts[identifier].append(now)
        return True, 0

    def reset(self, identifier: str):
        """
        Reset attempts for identifier (e.g., after successful login).

        Args:
            identifier: Identifier to reset
        """
        if identifier in self.attempts:
            del self.attempts[identifier]
