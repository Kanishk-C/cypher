"""Authentication and recovery management."""

import os
import uuid
import logging
import secrets
from src.core.crypto import (
    hash_password,
    generate_salt,
    derive_device_keys,
    derive_recovery_keys,
    SecureMemory,
    IntegrityVerifier,
    SecureFileHandler,
    safe_string_compare,
    RateLimiter,  # FIXED: Consolidated import
)
from src.data.database import (
    get_device_token_path,
    get_god_key_store_path as get_god_key_path,
    get_recovery_store_path as get_recovery_key_path,
    get_profiles_db_path,
)
from src.ui import views
from src.ui.colors import Colors
from src.utils.validators import InputValidator
from src.config import Config
from src.exceptions import CoreException, DecryptionError
from src.core.secure_string import SecureString

# FIXED: Use Config constants instead of hardcoded values
_recovery_rate_limiter = RateLimiter(
    max_attempts=Config.RECOVERY_MAX_ATTEMPTS, lockout_time=Config.RECOVERY_LOCKOUT_TIME
)


def initial_setup():
    """First-time setup with recovery phrase."""
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║     Welcome to Cypher: First-Time Setup                  ║")
    print("╚═══════════════════════════════════════════════════════════╝")

    print(
        f"\n{Colors.BRIGHT_YELLOW}Step 1: Create Your Secret Recovery Phrase{Colors.RESET}"
    )
    print("This is the ONLY way to restore your data on a new device.\n")

    while True:
        recovery_phrase = views.prompt_password_masked(
            f"Enter recovery phrase (min {Config.MIN_RECOVERY_PHRASE_WORDS} words): "
        ).strip()
        valid, msg = InputValidator.validate_recovery_phrase(recovery_phrase)
        if valid:
            break
        print(f"{Colors.BRIGHT_RED}✗ {msg}{Colors.RESET}")

    confirm_phrase = views.prompt_password_masked("Confirm recovery phrase: ").strip()

    with SecureString(recovery_phrase) as s_phrase, SecureString(
        confirm_phrase
    ) as s_confirm:

        if not safe_string_compare(s_phrase.get(), s_confirm.get()):
            print(
                f"{Colors.BRIGHT_RED}✗ Recovery phrases do not match. Setup aborted.{Colors.RESET}"
            )
            return

        # Store recovery phrase for later use
        recovery_phrase_copy = s_phrase.get()

    print(f"{Colors.BRIGHT_GREEN}✓ Recovery phrase set{Colors.RESET}")
    print(
        f"\n{Colors.BRIGHT_YELLOW}Step 2: Generating Cryptographic Keys{Colors.RESET}"
    )

    with SecureMemory(secrets.token_bytes(Config.KEY_SIZE_BYTES)) as god_key_mem:
        god_key = god_key_mem.get()
        device_token = uuid.uuid4().bytes

        # Store device token
        SecureFileHandler.write_secure(
            get_device_token_path(), device_token, mode=0o600
        )

        # Create device-bound god key
        salt_device = generate_salt()
        enc_key, hmac_key = derive_device_keys(device_token, salt_device)
        protected_god_key_device = IntegrityVerifier.protect_data(
            god_key, enc_key, hmac_key
        )
        SecureFileHandler.write_secure(
            get_god_key_path(), salt_device + protected_god_key_device, mode=0o600
        )

        # CRITICAL FIX: Create recovery-phrase-bound god key
        salt_recovery = generate_salt()
        enc_key_rec, hmac_key_rec = derive_recovery_keys(
            recovery_phrase_copy, salt_recovery
        )
        protected_god_key_recovery = IntegrityVerifier.protect_data(
            god_key, enc_key_rec, hmac_key_rec
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

    allowed, wait_time = _recovery_rate_limiter.check_attempt("recovery_system")
    if not allowed:
        print(
            f"{Colors.BRIGHT_RED}✗ Too many recovery attempts. "
            f"Please wait {wait_time//60} minutes.{Colors.RESET}"
        )
        logging.warning("Recovery rate limit exceeded")
        return False

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

    with SecureString(recovery_phrase) as s_phrase:
        try:
            recovery_store = SecureFileHandler.read_secure(get_recovery_key_path())
            if not recovery_store:
                print(
                    f"{Colors.BRIGHT_RED}✗ Recovery data not found. Has initial setup been completed?{Colors.RESET}"
                )
                logging.error(
                    "Recovery file not found during recovery attempt"
                )  # FIXED: Added logging
                return False

            salt = recovery_store[: Config.SALT_SIZE_BYTES]
            protected_god_key = recovery_store[Config.SALT_SIZE_BYTES :]

            enc_key, hmac_key = derive_recovery_keys(s_phrase.get(), salt)

            with SecureMemory(
                IntegrityVerifier.verify_and_decrypt(
                    protected_god_key, enc_key, hmac_key
                )
            ) as god_key_mem:
                god_key = god_key_mem.get()

                # Create NEW device token
                new_device_token = uuid.uuid4().bytes
                salt_device = generate_salt()
                enc_key_dev, hmac_key_dev = derive_device_keys(
                    new_device_token, salt_device
                )
                protected_god_key_device = IntegrityVerifier.protect_data(
                    god_key, enc_key_dev, hmac_key_dev
                )

                # Write the new device token and god key
                SecureFileHandler.write_secure(
                    get_device_token_path(), new_device_token, mode=0o600
                )
                SecureFileHandler.write_secure(
                    get_god_key_path(),
                    salt_device + protected_god_key_device,
                    mode=0o600,
                )

            # RESET RATE LIMITER ON SUCCESS
            _recovery_rate_limiter.reset("recovery_system")

            print(
                f"{Colors.BRIGHT_GREEN}✓ Recovery successful! Device re-bound.{Colors.RESET}"
            )
            logging.info("Account recovery successful")
            return True

        except (DecryptionError, CoreException) as e:
            # Don't reset rate limiter on failure
            print(
                f"{Colors.BRIGHT_RED}✗ Recovery failed: Incorrect recovery phrase{Colors.RESET}"
            )
            logging.error(f"Recovery failed: {e}")
            return False
        except Exception as e:
            # FIXED: More specific error message and better logging
            print(f"{Colors.BRIGHT_RED}✗ Recovery failed: {str(e)}{Colors.RESET}")
            logging.error(
                f"Unexpected recovery exception: {e}", exc_info=True
            )  # FIXED: Added exc_info
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
                if not device_token:
                    logging.error(
                        "Device token still missing after recovery"
                    )  # FIXED: Added logging
                    return None, None
            else:
                return None, None

        key_store = SecureFileHandler.read_secure(get_god_key_path())
        if not key_store:
            print(
                f"{Colors.BRIGHT_YELLOW}⚠ Key store missing. Recovery needed.{Colors.RESET}\n"
            )
            if recover_access():
                # Retry after recovery
                return unlock_session()
            else:
                return None, None

        salt = key_store[: Config.SALT_SIZE_BYTES]
        protected_god_key = key_store[Config.SALT_SIZE_BYTES :]

        # Use device token for key derivation
        enc_key, hmac_key = derive_device_keys(device_token, salt)

        try:
            raw_god_key = IntegrityVerifier.verify_and_decrypt(
                protected_god_key, enc_key, hmac_key
            )
        except CoreException as e:  # FIXED: Added exception binding
            print(
                f"{Colors.BRIGHT_YELLOW}⚠ Cannot decrypt with device token. Recovery needed.{Colors.RESET}\n"
            )
            logging.warning(
                f"Device token decryption failed: {e}"
            )  # FIXED: Added logging
            if recover_access():
                return unlock_session()
            return None, None

        session_god_key = (raw_god_key[:32], raw_god_key[32:])

    except Exception as e:
        print(f"{Colors.BRIGHT_RED}✗ Device authentication failed: {e}{Colors.RESET}")
        logging.error(
            f"Session unlock exception: {e}", exc_info=True
        )  # FIXED: Added exc_info
        return None, None

    profiles_conn = db_connect()
    profiles_db_path = get_profiles_db_path()

    if not os.path.exists(profiles_db_path):
        initialize_profiles_db(profiles_conn)
    else:
        try:
            protected_db = SecureFileHandler.read_secure(profiles_db_path)
            if not protected_db:
                raise CoreException("Profiles database is empty.")

            decrypted = IntegrityVerifier.verify_and_decrypt(
                protected_db, session_god_key[0], session_god_key[1]
            )
            profiles_conn.executescript(decrypted.decode("utf-8"))
        except CoreException as e:
            print(
                f"{Colors.BRIGHT_RED}✗ Could not decrypt profiles database: {e.message}{Colors.RESET}"
            )
            logging.error(
                f"Profiles database decryption failed: {e}"
            )  # FIXED: Added logging
            profiles_conn.close()
            return None, None

    return session_god_key, profiles_conn
