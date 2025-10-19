"""Authentication and recovery management."""

import os
import uuid
import getpass
import logging
from datetime import datetime
from src.core.crypto import (
    hash_password,
    generate_salt,
    derive_device_keys,
    derive_recovery_keys,
    SecureMemory,
    IntegrityVerifier,
    SecureFileHandler,
)
from src.data.database import (
    get_device_token_path,
    get_god_key_store_path as get_god_key_path,
    get_recovery_store_path as get_recovery_key_path,
    get_profiles_db_path,
)
from src.ui.colors import Colors
from src.ui import views
from src.utils.validators import InputValidator
from src.config import Config
from src.exceptions import CoreException


def initial_setup():
    """First-time setup with recovery phrase."""
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║     Welcome to Cypher: First-Time Setup                  ║")
    print("╚═══════════════════════════════════════════════════════════╝")

    # Get recovery phrase
    print(
        f"\n{Colors.BRIGHT_YELLOW}Step 1: Create Your Secret Recovery Phrase{Colors.RESET}"
    )
    print("This is the ONLY way to restore your data on a new device.")
    print("Store it safely - write it down on paper!\n")

    while True:
        recovery_phrase = views.prompt_password_masked(
            f"Enter recovery phrase (min {Config.MIN_RECOVERY_PHRASE_WORDS} words): "
        ).strip()

        valid, msg = InputValidator.validate_recovery_phrase(recovery_phrase)
        if valid:
            break
        print(f"{Colors.BRIGHT_RED}✗ {msg}{Colors.RESET}")

    # Confirm recovery phrase
    confirm_phrase = views.prompt_password_masked("Confirm recovery phrase: ").strip()
    if recovery_phrase != confirm_phrase:
        print(
            f"{Colors.BRIGHT_RED}✗ Recovery phrases do not match. Setup aborted.{Colors.RESET}"
        )
        return

    print(f"{Colors.BRIGHT_GREEN}✓ Recovery phrase set{Colors.RESET}")

    # Generate master keys
    print(
        f"\n{Colors.BRIGHT_YELLOW}Step 2: Generating Cryptographic Keys{Colors.RESET}"
    )

    with SecureMemory(os.urandom(Config.KEY_SIZE_BYTES)) as god_key_mem:
        god_key = god_key_mem.get()
        device_token = uuid.uuid4().bytes

        # Save device token
        SecureFileHandler.write_secure(
            get_device_token_path(), device_token, mode=0o600
        )

        # Encrypt God Key with device token
        salt_device = generate_salt()
        enc_key, hmac_key = derive_device_keys(device_token, salt_device)
        protected_god_key_device = IntegrityVerifier.protect_data(
            god_key, enc_key, hmac_key
        )
        SecureFileHandler.write_secure(
            get_god_key_path(), salt_device + protected_god_key_device, mode=0o600
        )

        # Encrypt God Key with recovery phrase
        salt_recovery = generate_salt()
        enc_key, hmac_key = derive_recovery_keys(recovery_phrase, salt_recovery)
        protected_god_key_recovery = IntegrityVerifier.protect_data(
            god_key, enc_key, hmac_key
        )
        SecureFileHandler.write_secure(
            get_recovery_key_path(),
            salt_recovery + protected_god_key_recovery,
            mode=0o600,
        )

    print(
        f"{Colors.BRIGHT_GREEN}✓ Cryptographic keys generated and secured{Colors.RESET}"
    )
    print(
        f"\n{Colors.BRIGHT_GREEN}╔═══════════════════════════════════════════════════════════╗"
    )
    print(f"║  Setup Complete! Your password manager is ready.         ║")
    print(
        f"╚═══════════════════════════════════════════════════════════╝{Colors.RESET}"
    )
    print(
        f"\n{Colors.BRIGHT_RED}⚠  IMPORTANT: Write down your recovery phrase NOW!{Colors.RESET}\n"
    )

    logging.info("Initial setup completed successfully")


def recover_access():
    """Recover access using recovery phrase."""
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║     Account Recovery                                      ║")
    print("╚═══════════════════════════════════════════════════════════╝\n")

    print(
        f"{Colors.BRIGHT_YELLOW}Enter your Secret Recovery Phrase to restore access.{Colors.RESET}\n"
    )

    recovery_phrase = views.prompt_password_masked("Recovery phrase: ").strip()

    if not recovery_phrase:
        print(f"{Colors.BRIGHT_RED}✗ Recovery cancelled{Colors.RESET}")
        return False

    try:
        # Read recovery-encrypted God Key
        recovery_store = SecureFileHandler.read_secure(get_recovery_key_path())
        if not recovery_store:
            raise CoreException("Recovery data not found.")

        salt = recovery_store[: Config.SALT_SIZE_BYTES]
        protected_god_key = recovery_store[Config.SALT_SIZE_BYTES :]

        # Decrypt God Key
        print(f"\n{Colors.BRIGHT_BLUE}⟳ Verifying recovery phrase...{Colors.RESET}")
        enc_key, hmac_key = derive_recovery_keys(recovery_phrase, salt)

        with SecureMemory(
            IntegrityVerifier.verify_and_decrypt(protected_god_key, enc_key, hmac_key)
        ) as god_key_mem:
            god_key = god_key_mem.get()

            # Generate new device token
            new_device_token = uuid.uuid4().bytes
            salt_device = generate_salt()
            enc_key, hmac_key = derive_device_keys(new_device_token, salt_device)
            protected_god_key_device = IntegrityVerifier.protect_data(
                god_key, enc_key, hmac_key
            )

            # Save new device binding
            SecureFileHandler.write_secure(
                get_device_token_path(), new_device_token, mode=0o600
            )
            SecureFileHandler.write_secure(
                get_god_key_path(), salt_device + protected_god_key_device, mode=0o600
            )

        print(
            f"{Colors.BRIGHT_GREEN}✓ Recovery successful! Device re-bound.{Colors.RESET}"
        )
        print(
            f"\n{Colors.BRIGHT_BLUE}ℹ You can now log in with your profile password.{Colors.RESET}"
        )
        logging.info("Account recovery successful")
        return True

    except Exception as e:
        print(
            f"{Colors.BRIGHT_RED}✗ Recovery failed: Incorrect recovery phrase{Colors.RESET}"
        )
        logging.error(f"Recovery exception: {e}")
        return False


def unlock_session():
    """Unlock session using device token. Returns (god_key, profiles_conn)."""
    from src.data.database import db_connect, initialize_profiles_db

    try:
        device_token = SecureFileHandler.read_secure(get_device_token_path())
        if not device_token:
            print(
                f"{Colors.BRIGHT_YELLOW}⚠ Device token not found. Recovery needed.{Colors.RESET}\n"
            )
            if recover_access():
                device_token = SecureFileHandler.read_secure(get_device_token_path())
                if not device_token:  # Add check after recovery attempt
                    return None, None
            else:
                return None, None

        key_store = SecureFileHandler.read_secure(get_god_key_path())
        if not key_store:
            raise CoreException("Key store missing or corrupted.")

        salt = key_store[: Config.SALT_SIZE_BYTES]
        protected_god_key = key_store[Config.SALT_SIZE_BYTES :]

        enc_key, hmac_key = derive_device_keys(device_token, salt)
        raw_god_key = IntegrityVerifier.verify_and_decrypt(
            protected_god_key, enc_key, hmac_key
        )
        session_god_key = (raw_god_key[:32], raw_god_key[32:])

    except Exception as e:
        print(f"{Colors.BRIGHT_RED}✗ Device authentication failed{Colors.RESET}")
        logging.error(f"Session unlock exception: {e}")
        return None, None

    profiles_conn = db_connect()
    profiles_db_path = get_profiles_db_path()

    if not os.path.exists(profiles_db_path):
        initialize_profiles_db(profiles_conn)
    else:
        try:
            protected_db = SecureFileHandler.read_secure(profiles_db_path)
            if not protected_db:
                raise CoreException("Profiles database is empty or could not be read.")

            decrypted = IntegrityVerifier.verify_and_decrypt(
                protected_db, session_god_key[0], session_god_key[1]
            )
            profiles_conn.executescript(decrypted.decode("utf-8"))
        except CoreException as e:
            print(
                f"{Colors.BRIGHT_RED}✗ Could not decrypt profiles database: {e.message}{Colors.RESET}"
            )
            profiles_conn.close()
            return None, None

    return session_god_key, profiles_conn
