"""Handles all cryptographic operations."""

import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from exceptions import DecryptionError
from config import Config


def derive_keys(password: bytes, salt: bytes, iterations: int) -> tuple:
    """
    Derive both encryption and HMAC keys from password.
    Returns: (encryption_key, hmac_key)
    """
    # Derive 64 bytes, split into two 32-byte keys
    kdf = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password,
        salt=salt,
        iterations=iterations,
        dklen=64,
    )
    enc_key = base64.urlsafe_b64encode(kdf[:32])
    hmac_key = kdf[32:]
    return enc_key, hmac_key


def derive_key_from_phrase(phrase: str, salt: bytes) -> tuple:
    """Derives encryption and HMAC keys from recovery phrase."""
    return derive_keys(
        phrase.encode("utf-8"),
        salt,
        Config.PBKDF2_ITERATIONS_RECOVERY
    )


def derive_key_from_device_token(token: bytes, salt: bytes) -> tuple:
    """Derives encryption and HMAC keys from device token."""
    return derive_keys(
        token,
        salt,
        Config.PBKDF2_ITERATIONS_DEVICE
    )


def derive_profile_specific_keys(master_password: str, profile_name: str, 
                                 creation_date: str, salt: bytes) -> tuple:
    """Derives encryption and HMAC keys for a user's profile."""
    key_material = f"{master_password}{profile_name}{creation_date}".encode('utf-8')
    return derive_keys(
        key_material,
        salt,
        Config.PBKDF2_ITERATIONS_PROFILE
    )


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypts data using Fernet (AES-128-CBC + HMAC)."""
    return Fernet(key).encrypt(data)


def decrypt_data(token: bytes, key: bytes) -> bytes:
    """Decrypts data. Raises DecryptionError on failure."""
    try:
        return Fernet(key).decrypt(token)
    except InvalidToken:
        raise DecryptionError("Decryption failed. Data may be corrupt or key is incorrect.")
