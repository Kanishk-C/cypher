"""Handles device-locked authentication and recovery."""

import getpass
import os
import bcrypt
import uuid
import base64
import logging
from argon2 import PasswordHasher
from argon2.exceptions import HashingError, VerifyMismatchError
from data import database
from core import encryption
from core.security import SecureFileHandler, IntegrityVerifier, SecureMemory
from interface import colors
from utils.validators import InputValidator
from exceptions import DecryptionError, CoreException
from config import Config

ph = PasswordHasher(
    time_cost=Config.ARGON2_TIME_COST,
    memory_cost=Config.ARGON2_MEMORY_COST,
    parallelism=Config.ARGON2_PARALLELISM,
    hash_len=Config.ARGON2_PASS_HASH_LEN,
    salt_len=Config.ARGON2_SALT_LEN
)


def hash_master_password(password: str) -> str:
    """Hashes a password using Argon2id."""
    try:
        return ph.hash(password)
    except HashingError as e:
        raise CoreException(f"Password hashing failed: {e}")


def verify_master_password(password_hash: str, password: str) -> bool:
    """Verifies a password against an Argon2id hash."""
    try:
        ph.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False
    except Exception as e:
        logging.error(f"Password verification error: {e}")
        return False


def initial_setup():
    """Handles first-time setup with recovery phrase support."""
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║     Welcome to Cypher: First-Time Setup                  ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    
    # Get recovery phrase
    print(f"\n{colors.Colors.BRIGHT_YELLOW}Step 1: Create Your Secret Recovery Phrase{colors.Colors.RESET}")
    print("This is the ONLY way to restore your data on a new device.")
    print("Store it safely - write it down on paper!\n")
    
    recovery_phrase = ""
    while True:
        recovery_phrase = getpass.getpass(
            f"Enter recovery phrase (min {Config.MIN_RECOVERY_PHRASE_WORDS} words): "
        ).strip()
        
        valid, msg = InputValidator.validate_recovery_phrase(recovery_phrase)
        if valid:
            break
        print(f"{colors.Colors.BRIGHT_RED}✗ {msg}{colors.Colors.RESET}")
    
    # Confirm recovery phrase
    confirm_phrase = getpass.getpass("Confirm recovery phrase: ").strip()
    if recovery_phrase != confirm_phrase:
        print(f"{colors.Colors.BRIGHT_RED}✗ Recovery phrases do not match. Setup aborted.{colors.Colors.RESET}")
        return
    
    print(f"{colors.Colors.BRIGHT_GREEN}✓ Recovery phrase set{colors.Colors.RESET}")
    
    # Generate master keys
    print(f"\n{colors.Colors.BRIGHT_YELLOW}Step 2: Generating Cryptographic Keys{colors.Colors.RESET}")
    
    with SecureMemory(os.urandom(Config.KEY_SIZE_BYTES)) as god_key_mem:
        god_key = god_key_mem.get()
        device_token = uuid.uuid4().bytes
        
        # Save device token
        SecureFileHandler.write_secure(
            database.get_device_token_path(),
            device_token,
            mode=0o600
        )
        
        # Encrypt God Key with device token
        salt_device = os.urandom(Config.SALT_SIZE_BYTES)
        enc_key, hmac_key = encryption.derive_key_from_device_token(device_token, salt_device)
        protected_god_key_device = IntegrityVerifier.protect_data(god_key, enc_key, hmac_key)
        
        SecureFileHandler.write_secure(
            database.get_god_key_store_path(),
            salt_device + protected_god_key_device,
            mode=0o600
        )
        
        # Encrypt God Key with recovery phrase
        salt_recovery = os.urandom(Config.SALT_SIZE_BYTES)
        enc_key, hmac_key = encryption.derive_key_from_phrase(recovery_phrase, salt_recovery)
        protected_god_key_recovery = IntegrityVerifier.protect_data(god_key, enc_key, hmac_key)
        
        SecureFileHandler.write_secure(
            database.get_recovery_store_path(),
            salt_recovery + protected_god_key_recovery,
            mode=0o600
        )
    
    print(f"{colors.Colors.BRIGHT_GREEN}✓ Cryptographic keys generated and secured{colors.Colors.RESET}")
    print(f"\n{colors.Colors.BRIGHT_GREEN}╔═══════════════════════════════════════════════════════════╗")
    print(f"║  Setup Complete! Your password manager is ready.         ║")
    print(f"╚═══════════════════════════════════════════════════════════╝{colors.Colors.RESET}")
    
    print(f"\n{colors.Colors.BRIGHT_RED}⚠  IMPORTANT: Write down your recovery phrase NOW!{colors.Colors.RESET}")
    print(f"{colors.Colors.BRIGHT_RED}   If you lose this device, you'll need it to recover.{colors.Colors.RESET}\n")
    
    logging.info("Initial setup completed successfully")


def recover_access():
    """Recover access using recovery phrase."""
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║     Account Recovery                                      ║")
    print("╚═══════════════════════════════════════════════════════════╝\n")
    
    print(f"{colors.Colors.BRIGHT_YELLOW}Enter your Secret Recovery Phrase to restore access.{colors.Colors.RESET}\n")
    
    recovery_phrase = getpass.getpass("Recovery phrase: ").strip()
    
    if not recovery_phrase:
        print(f"{colors.Colors.BRIGHT_RED}✗ Recovery cancelled{colors.Colors.RESET}")
        return False
    
    try:
        # Read recovery-encrypted God Key
        recovery_store = SecureFileHandler.read_secure(database.get_recovery_store_path())
        if not recovery_store:
            raise CoreException("Recovery data not found. Cannot recover.")
        
        salt = recovery_store[:Config.SALT_SIZE_BYTES]
        protected_god_key = recovery_store[Config.SALT_SIZE_BYTES:]
        
        # Decrypt God Key with recovery phrase
        print(f"\n{colors.Colors.BRIGHT_BLUE}⟳ Verifying recovery phrase...{colors.Colors.RESET}")
        enc_key, hmac_key = encryption.derive_key_from_phrase(recovery_phrase, salt)
        
        with SecureMemory(IntegrityVerifier.verify_and_decrypt(protected_god_key, enc_key, hmac_key)) as god_key_mem:
            god_key = god_key_mem.get()
            
            # Generate new device token
            new_device_token = uuid.uuid4().bytes
            salt_device = os.urandom(Config.SALT_SIZE_BYTES)
            enc_key, hmac_key = encryption.derive_key_from_device_token(new_device_token, salt_device)
            protected_god_key_device = IntegrityVerifier.protect_data(god_key, enc_key, hmac_key)
            
            # Save new device binding
            SecureFileHandler.write_secure(
                database.get_device_token_path(),
                new_device_token,
                mode=0o600
            )
            SecureFileHandler.write_secure(
                database.get_god_key_store_path(),
                salt_device + protected_god_key_device,
                mode=0o600
            )
        
        print(f"{colors.Colors.BRIGHT_GREEN}✓ Recovery successful! Device re-bound.{colors.Colors.RESET}")
        print(f"\n{colors.Colors.BRIGHT_BLUE}ℹ You can now log in with your profile password.{colors.Colors.RESET}")
        logging.info("Account recovery successful")
        return True
        
    except CoreException as e:
        print(f"{colors.Colors.BRIGHT_RED}✗ Recovery failed: {e.message}{colors.Colors.RESET}")
        logging.error(f"Recovery failed: {e.message}")
        return False
    except Exception as e:
        print(f"{colors.Colors.BRIGHT_RED}✗ Recovery failed: Incorrect recovery phrase or corrupted data{colors.Colors.RESET}")
        logging.error(f"Recovery exception: {e}")
        return False


def unlock_session():
    """
    Unlocks session using device token.
    Returns the Session God Key and profiles DB connection.
    """
    try:
        device_token = SecureFileHandler.read_secure(database.get_device_token_path())
        if not device_token:
            print(f"{colors.Colors.BRIGHT_YELLOW}⚠ Device token not found. Recovery needed.{colors.Colors.RESET}\n")
            if recover_access():
                # Retry unlock after recovery
                device_token = SecureFileHandler.read_secure(database.get_device_token_path())
            else:
                return None, None
        
        key_store_content = SecureFileHandler.read_secure(database.get_god_key_store_path())
        if not key_store_content:
            raise CoreException("Key store is missing or corrupted.")
        
        salt = key_store_content[:Config.SALT_SIZE_BYTES]
        protected_god_key = key_store_content[Config.SALT_SIZE_BYTES:]
        
        # Decrypt God Key
        enc_key, hmac_key = encryption.derive_key_from_device_token(device_token, salt)
        raw_god_key = IntegrityVerifier.verify_and_decrypt(protected_god_key, enc_key, hmac_key)
        session_god_key = (raw_god_key[:32], raw_god_key[32:])
        
    except CoreException as e:
        print(f"{colors.Colors.BRIGHT_RED}✗ Authentication failed: {e.message}{colors.Colors.RESET}")
        logging.error(f"Session unlock failed: {e.message}")
        return None, None
    except Exception as e:
        print(f"{colors.Colors.BRIGHT_RED}✗ Device authentication failed. Files may be tampered.{colors.Colors.RESET}")
        logging.error(f"Session unlock exception: {e}")
        return None, None
    
    # Load profiles database
    profiles_conn = database.db_connect()
    profiles_db_path = database.get_profiles_db_path()
    
    if not os.path.exists(profiles_db_path):
        database.initialize_profiles_db(profiles_conn)
    else:
        try:
            protected_profiles_db = SecureFileHandler.read_secure(profiles_db_path)
            decrypted_db_bytes = IntegrityVerifier.verify_and_decrypt(
                protected_profiles_db,
                session_god_key[0],
                session_god_key[1]
            )
            profiles_conn.executescript(decrypted_db_bytes.decode("utf-8"))
        except CoreException as e:
            print(f"{colors.Colors.BRIGHT_RED}✗ Could not decrypt profiles database: {e.message}{colors.Colors.RESET}")
            profiles_conn.close()
            return None, None
    
    return session_god_key, profiles_conn