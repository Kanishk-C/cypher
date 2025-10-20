"""Authentication and recovery management - v1.0.0 PRODUCTION READY."""

import os
import uuid
import logging
import secrets
from typing import Optional, Tuple

from src.core.crypto import (
    hash_password,
    generate_salt,
    derive_device_keys,
    derive_recovery_keys,
    SecureMemory,
    IntegrityVerifier,
    SecureFileHandler,
    safe_string_compare,
    RateLimiter,
)
from src.data.database import (
    get_device_token_path,
    get_god_key_store_path as get_god_key_path,
    get_recovery_store_path as get_recovery_key_path,
    get_profiles_db_path,
    db_connect,
    initialize_profiles_db,
)
from src.ui import views
from src.ui.colors import Colors
from src.utils.validators import InputValidator
from src.config import Config
from src.exceptions import CoreException, DecryptionError
from src.core.secure_string import SecureString


# Recovery rate limiter - prevents brute force attacks on recovery phrase
_recovery_rate_limiter = RateLimiter(
    max_attempts=Config.RECOVERY_MAX_ATTEMPTS,
    lockout_time=Config.RECOVERY_LOCKOUT_TIME,
)


def verify_recovery_key_integrity(recovery_phrase: str) -> bool:
    """
    Verify recovery key file can be decrypted with given phrase.

    This ensures the recovery key was written correctly and can be used later.

    Args:
        recovery_phrase: Recovery phrase to test

    Returns:
        True if recovery key is valid and can be decrypted
    """
    try:
        recovery_store = SecureFileHandler.read_secure(get_recovery_key_path())

        if not recovery_store:
            logging.error("Recovery key file not found during verification")
            return False

        if len(recovery_store) < Config.SALT_SIZE_BYTES + 32:
            logging.error("Recovery key file too short - corrupted")
            return False

        # Extract salt and protected god key
        salt = recovery_store[: Config.SALT_SIZE_BYTES]
        protected_god_key = recovery_store[Config.SALT_SIZE_BYTES :]

        # Derive keys from recovery phrase
        enc_key, hmac_key = derive_recovery_keys(recovery_phrase, salt)

        # Attempt to decrypt
        try:
            god_key = IntegrityVerifier.verify_and_decrypt(
                protected_god_key, enc_key, hmac_key
            )

            # Verify decrypted key is correct length
            if len(god_key) != Config.KEY_SIZE_BYTES:
                logging.error(
                    f"Decrypted god key wrong size: {len(god_key)} != {Config.KEY_SIZE_BYTES}"
                )
                return False

            logging.info("Recovery key verification successful")
            return True

        except (CoreException, DecryptionError) as e:
            logging.error(f"Recovery key verification failed: {e}")
            return False

    except Exception as e:
        logging.error(f"Unexpected error during recovery key verification: {e}")
        return False


def initial_setup():
    """
    First-time setup with recovery phrase and cryptographic key generation.

    Creates:
    - Device token (for this device)
    - God key (master encryption key)
    - Device-bound god key (encrypted with device token)
    - Recovery-bound god key (encrypted with recovery phrase)

    Process:
    1. Prompt for recovery phrase (with validation)
    2. Generate cryptographic keys
    3. Store device token
    4. Store device-bound god key
    5. Store recovery-bound god key
    6. Verify recovery key integrity
    """
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║     Welcome to Cypher: First-Time Setup                  ║")
    print("╚═══════════════════════════════════════════════════════════╝")

    print(
        f"\n{Colors.BRIGHT_YELLOW}Step 1: Create Your Secret Recovery Phrase{Colors.RESET}"
    )
    print("This is the ONLY way to restore your data on a new device.")
    print(f"{Colors.BRIGHT_RED}⚠  Keep this phrase secret and secure!{Colors.RESET}\n")

    # Prompt for recovery phrase with validation
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

    # Use SecureString for comparison
    with SecureString(recovery_phrase) as s_phrase, SecureString(
        confirm_phrase
    ) as s_confirm:
        if not safe_string_compare(s_phrase.get(), s_confirm.get()):
            print(
                f"{Colors.BRIGHT_RED}✗ Recovery phrases do not match. Setup aborted.{Colors.RESET}"
            )
            logging.warning("Recovery phrase mismatch during setup")
            return

        # Store recovery phrase for use in this function
        recovery_phrase_copy = s_phrase.get()

    print(f"{Colors.BRIGHT_GREEN}✓ Recovery phrase set{Colors.RESET}")
    print(
        f"\n{Colors.BRIGHT_YELLOW}Step 2: Generating Cryptographic Keys{Colors.RESET}"
    )
    print("This may take a few seconds...")

    try:
        # Generate master god key (random)
        with SecureMemory(secrets.token_bytes(Config.KEY_SIZE_BYTES)) as god_key_mem:
            god_key = god_key_mem.get()

            # Generate device token (unique to this device)
            device_token = uuid.uuid4().bytes

            # === STEP 1: Store device token ===
            SecureFileHandler.write_secure(
                get_device_token_path(), device_token, mode=0o600
            )
            logging.info("Device token created")

            # === STEP 2: Create and store device-bound god key ===
            salt_device = generate_salt()
            enc_key_device, hmac_key_device = derive_device_keys(
                device_token, salt_device
            )
            protected_god_key_device = IntegrityVerifier.protect_data(
                god_key, enc_key_device, hmac_key_device
            )

            SecureFileHandler.write_secure(
                get_god_key_path(),
                salt_device + protected_god_key_device,
                mode=0o600,
            )
            logging.info("Device-bound god key created")

            # === STEP 3: Create and store recovery-bound god key ===
            salt_recovery = generate_salt()
            enc_key_recovery, hmac_key_recovery = derive_recovery_keys(
                recovery_phrase_copy, salt_recovery
            )
            protected_god_key_recovery = IntegrityVerifier.protect_data(
                god_key, enc_key_recovery, hmac_key_recovery
            )

            SecureFileHandler.write_secure(
                get_recovery_key_path(),
                salt_recovery + protected_god_key_recovery,
                mode=0o600,
            )
            logging.info("Recovery-bound god key created")

        # === STEP 4: VERIFY RECOVERY KEY ===
        print(
            f"{Colors.BRIGHT_YELLOW}⟳ Verifying recovery key...{Colors.RESET}",
            end="",
            flush=True,
        )

        if not verify_recovery_key_integrity(recovery_phrase_copy):
            # Recovery key verification FAILED
            print("\r" + " " * 50 + "\r", end="", flush=True)  # Clear line
            print(
                f"{Colors.BRIGHT_RED}✗ CRITICAL: Recovery key verification failed!{Colors.RESET}"
            )
            print(
                f"{Colors.BRIGHT_RED}Your recovery phrase may not work correctly.{Colors.RESET}"
            )
            print(f"{Colors.BRIGHT_YELLOW}Please run setup again.{Colors.RESET}")

            # Clean up potentially corrupted files
            try:
                if os.path.exists(get_recovery_key_path()):
                    os.unlink(get_recovery_key_path())
                if os.path.exists(get_god_key_path()):
                    os.unlink(get_god_key_path())
                if os.path.exists(get_device_token_path()):
                    os.unlink(get_device_token_path())
            except Exception as cleanup_error:
                logging.error(f"Cleanup failed: {cleanup_error}")

            logging.critical("Recovery key verification failed - setup aborted")
            return

        # Success!
        print("\r" + " " * 50 + "\r", end="", flush=True)  # Clear line
        print(
            f"{Colors.BRIGHT_GREEN}✓ Cryptographic keys generated and verified{Colors.RESET}"
        )

        print(
            f"\n{Colors.BRIGHT_GREEN}╔═══════════════════════════════════════════════════════════╗"
        )
        print(f"║  Setup Complete! Your password manager is ready.         ║")
        print(
            f"╚═══════════════════════════════════════════════════════════╝{Colors.RESET}"
        )
        print(
            f"\n{Colors.BRIGHT_RED}⚠  IMPORTANT: Write down your recovery phrase NOW!{Colors.RESET}"
        )
        print(
            f"{Colors.BRIGHT_YELLOW}   Keep it in a secure location separate from this device.{Colors.RESET}\n"
        )

        logging.info("Initial setup completed successfully with verification")

    except Exception as e:
        print(f"\n{Colors.BRIGHT_RED}✗ Setup failed: {e}{Colors.RESET}")
        logging.exception("Initial setup failed")

        # Attempt cleanup
        try:
            for path in [
                get_recovery_key_path(),
                get_god_key_path(),
                get_device_token_path(),
            ]:
                if os.path.exists(path):
                    os.unlink(path)
        except Exception as cleanup_error:
            logging.error(f"Cleanup failed: {cleanup_error}")


def recover_access() -> bool:
    """
    Recover access using recovery phrase.

    This allows regaining access after:
    - Device loss
    - Device token corruption
    - God key corruption

    Process:
    1. Check rate limit
    2. Prompt for recovery phrase
    3. Decrypt god key using recovery phrase
    4. Generate new device token
    5. Re-encrypt god key with new device token
    6. Reset rate limiter on success

    Returns:
        True if recovery successful, False otherwise
    """
    # Check rate limit
    allowed, wait_time = _recovery_rate_limiter.check_attempt("recovery_system")

    if not allowed:
        print(
            f"{Colors.BRIGHT_RED}✗ Too many recovery attempts. "
            f"Please wait {wait_time // 60} minutes.{Colors.RESET}"
        )
        logging.warning("Recovery rate limit exceeded")
        return False

    # Display recovery UI
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║     Account Recovery                                      ║")
    print("╚═══════════════════════════════════════════════════════════╝\n")
    print(
        f"{Colors.BRIGHT_YELLOW}Enter your Secret Recovery Phrase to restore access.{Colors.RESET}\n"
    )

    # Prompt for recovery phrase
    recovery_phrase = views.prompt_password_masked("Recovery phrase: ").strip()

    if not recovery_phrase:
        print(f"{Colors.BRIGHT_RED}✗ Recovery cancelled{Colors.RESET}")
        logging.info("Recovery cancelled by user")
        return False

    # Attempt recovery with SecureString
    with SecureString(recovery_phrase) as s_phrase:
        try:
            # Read recovery key file
            recovery_store = SecureFileHandler.read_secure(get_recovery_key_path())

            if not recovery_store:
                print(
                    f"{Colors.BRIGHT_RED}✗ Recovery data not found. "
                    f"Has initial setup been completed?{Colors.RESET}"
                )
                logging.warning("Recovery file not found during recovery attempt")
                return False

            # Extract salt and protected god key
            salt = recovery_store[: Config.SALT_SIZE_BYTES]
            protected_god_key = recovery_store[Config.SALT_SIZE_BYTES :]

            # Derive keys from recovery phrase
            enc_key, hmac_key = derive_recovery_keys(s_phrase.get(), salt)

            # Decrypt god key
            with SecureMemory(
                IntegrityVerifier.verify_and_decrypt(
                    protected_god_key, enc_key, hmac_key
                )
            ) as god_key_mem:
                god_key = god_key_mem.get()

                # Generate NEW device token
                new_device_token = uuid.uuid4().bytes
                salt_device = generate_salt()

                # Encrypt god key with new device token
                enc_key_dev, hmac_key_dev = derive_device_keys(
                    new_device_token, salt_device
                )
                protected_god_key_device = IntegrityVerifier.protect_data(
                    god_key, enc_key_dev, hmac_key_dev
                )

                # Write new device token and god key
                SecureFileHandler.write_secure(
                    get_device_token_path(), new_device_token, mode=0o600
                )
                SecureFileHandler.write_secure(
                    get_god_key_path(),
                    salt_device + protected_god_key_device,
                    mode=0o600,
                )

            # SUCCESS - Reset rate limiter
            _recovery_rate_limiter.reset("recovery_system")

            print(
                f"{Colors.BRIGHT_GREEN}✓ Recovery successful! Device re-bound.{Colors.RESET}"
            )
            logging.info("Account recovery successful")
            return True

        except (DecryptionError, CoreException) as e:
            # Expected failures - don't reset rate limiter
            print(
                f"{Colors.BRIGHT_RED}✗ Recovery failed: Incorrect recovery phrase{Colors.RESET}"
            )
            logging.warning(f"Recovery failed - incorrect phrase: {e}")
            return False

        except Exception as e:
            # Unexpected failures
            print(f"{Colors.BRIGHT_RED}✗ Recovery failed: {str(e)}{Colors.RESET}")
            logging.error(f"Unexpected recovery exception: {e}", exc_info=True)
            return False


def unlock_session() -> Tuple[Optional[Tuple[bytes, bytes]], Optional[object]]:
    """
    Unlock session using device token.

    This is the normal startup path - uses device-bound god key.
    Falls back to recovery if device token is missing or invalid.

    Returns:
        Tuple of (session_god_key, profiles_conn) where:
        - session_god_key: Tuple of (encryption_key, hmac_key)
        - profiles_conn: SQLite connection to profiles database
        Returns (None, None) on failure
    """
    try:
        # === STEP 1: Read device token ===
        device_token = SecureFileHandler.read_secure(get_device_token_path())

        if not device_token:
            print(
                f"{Colors.BRIGHT_YELLOW}⚠ Device token not found. Recovery needed.{Colors.RESET}\n"
            )
            logging.info("Device token not found - initiating recovery")

            if recover_access():
                # Retry after recovery
                device_token = SecureFileHandler.read_secure(get_device_token_path())
                if not device_token:
                    logging.error("Device token still missing after recovery")
                    return None, None
            else:
                logging.info("Recovery declined or failed")
                return None, None

        # === STEP 2: Read god key store ===
        key_store = SecureFileHandler.read_secure(get_god_key_path())

        if not key_store:
            print(
                f"{Colors.BRIGHT_YELLOW}⚠ Key store missing. Recovery needed.{Colors.RESET}\n"
            )
            logging.info("God key store not found - initiating recovery")

            if recover_access():
                # Retry entire unlock process
                return unlock_session()
            else:
                logging.info("Recovery declined or failed")
                return None, None

        # === STEP 3: Extract salt and protected god key ===
        salt = key_store[: Config.SALT_SIZE_BYTES]
        protected_god_key = key_store[Config.SALT_SIZE_BYTES :]

        # === STEP 4: Decrypt god key using device token ===
        enc_key, hmac_key = derive_device_keys(device_token, salt)

        try:
            raw_god_key = IntegrityVerifier.verify_and_decrypt(
                protected_god_key, enc_key, hmac_key
            )
        except CoreException as e:
            # Device token doesn't work - need recovery
            print(
                f"{Colors.BRIGHT_YELLOW}⚠ Cannot decrypt with device token. "
                f"Recovery needed.{Colors.RESET}\n"
            )
            logging.warning(f"Device token decryption failed: {e}")

            if recover_access():
                # Retry entire unlock process
                return unlock_session()
            else:
                return None, None

        # === STEP 5: Split god key into encryption and HMAC keys ===
        session_god_key = (raw_god_key[:32], raw_god_key[32:])

    except Exception as e:
        print(f"{Colors.BRIGHT_RED}✗ Device authentication failed: {e}{Colors.RESET}")
        logging.error(f"Session unlock exception: {e}", exc_info=True)
        return None, None

    # === STEP 6: Load profiles database ===
    profiles_conn = db_connect()
    profiles_db_path = get_profiles_db_path()

    if not os.path.exists(profiles_db_path):
        # First run - initialize empty database
        initialize_profiles_db(profiles_conn)
        logging.info("Initialized new profiles database")

    else:
        # Load existing database
        try:
            protected_db = SecureFileHandler.read_secure(profiles_db_path)

            if not protected_db:
                raise CoreException("Profiles database is empty.")

            # Decrypt and load database
            decrypted = IntegrityVerifier.verify_and_decrypt(
                protected_db, session_god_key[0], session_god_key[1]
            )
            profiles_conn.executescript(decrypted.decode("utf-8"))
            logging.info("Profiles database loaded successfully")

        except CoreException as e:
            print(
                f"{Colors.BRIGHT_RED}✗ Could not decrypt profiles database: "
                f"{e.message}{Colors.RESET}"
            )
            logging.error(f"Profiles database decryption failed: {e}")
            profiles_conn.close()
            return None, None

    return session_god_key, profiles_conn
