"""Handles all cryptographic operations."""

import base64
import os
from argon2.low_level import hash_secret, Type as Argon2Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from exceptions import DecryptionError
from config import Config


def derive_keys(password: bytes, salt: bytes) -> tuple:
    """
    Derive both encryption and HMAC keys from password using Argon2id.
    Returns: (encryption_key, hmac_key) as raw bytes.
    """
    kdf = hash_secret(
        secret=password,
        salt=salt,
        time_cost=Config.ARGON2_TIME_COST,
        memory_cost=Config.ARGON2_MEMORY_COST,
        parallelism=Config.ARGON2_PARALLELISM,
        hash_len=Config.ARGON2_KEY_LEN,
        type=Argon2Type.ID
    )
    # Use first 32 bytes for AES key, next 32 for HMAC key
    enc_key = kdf[:32]
    hmac_key = kdf[32:]
    return enc_key, hmac_key


def derive_key_from_phrase(phrase: str, salt: bytes) -> tuple:
    """Derives encryption and HMAC keys from recovery phrase."""
    return derive_keys(
        phrase.encode("utf-8"),
        salt,
    )


def derive_key_from_device_token(token: bytes, salt: bytes) -> tuple:
    """Derives encryption and HMAC keys from device token."""
    return derive_keys(
        token,
        salt,
    )


def derive_profile_specific_keys(master_password: str, profile_name: str, 
                                 creation_date: str, salt: bytes) -> tuple:
    """Derives encryption and HMAC keys for a user's profile."""
    key_material = f"{master_password}{profile_name}{creation_date}".encode('utf-8')
    return derive_keys(
        key_material,
        salt,
    )


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypts data using AES-256-GCM."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # GCM recommended nonce size
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext  # Prepend nonce to ciphertext


def decrypt_data(token: bytes, key: bytes) -> bytes:
    """Decrypts data. Raises DecryptionError on failure."""
    try:
        aesgcm = AESGCM(key)
        nonce = token[:12]
        ciphertext = token[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise DecryptionError("Decryption failed. Data may be corrupt or key is incorrect.")