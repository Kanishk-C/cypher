"""Authentication and recovery management."""

import os
import uuid
import logging
import secrets
import platform
import hashlib
from src.core.crypto import (
    hash_password,
    generate_salt,
    derive_device_keys,
    derive_recovery_keys,
    SecureMemory,
    IntegrityVerifier,
    SecureFileHandler,
    safe_string_compare,
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
from src.core.crypto import RateLimiter
from src.exceptions import CoreException, DecryptionError
from src.core.secure_string import SecureString

_recovery_rate_limiter = RateLimiter(
    max_attempts=5, lockout_time=3600
)  # 1 hour lockout


def get_hardware_fingerprint() -> bytes:
    """
    Generate a hardware-specific fingerprint.
    Warning: This will break if hardware changes!
    """
    components = [
        platform.node(),  # Computer name
        platform.machine(),  # Machine type
        platform.processor(),  # Processor info
    ]

    # On Windows, add volume serial number
    if platform.system() == "Windows":
        try:
            import win32api

            volume_info = win32api.GetVolumeInformation("C:\\")
            components.append(str(volume_info[1]))  # Serial number
        except:
            pass

    # On Linux/Mac, use machine-id
    elif platform.system() in ("Linux", "Darwin"):
        try:
            if os.path.exists("/etc/machine-id"):
                with open("/etc/machine-id", "r") as f:
                    components.append(f.read().strip())
        except:
            pass

    fingerprint = hashlib.sha256("|".join(components).encode()).digest()

    return fingerprint


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

    print(f"{Colors.BRIGHT_GREEN}✓ Recovery phrase set{Colors.RESET}")
    print(
        f"\n{Colors.BRIGHT_YELLOW}Step 2: Generating Cryptographic Keys{Colors.RESET}"
    )

    with SecureMemory(secrets.token_bytes(Config.KEY_SIZE_BYTES)) as god_key_mem:
        god_key = god_key_mem.get()

        # BIND TO HARDWARE
        hardware_fp = get_hardware_fingerprint()
        device_token = uuid.uuid4().bytes

        # Combine device token with hardware fingerprint
        bound_token = hashlib.sha256(device_token + hardware_fp).digest()

        # Store only the device token (not hardware FP)
        SecureFileHandler.write_secure(
            get_device_token_path(), device_token, mode=0o600
        )

        # Use BOUND token for key derivation
        salt_device = generate_salt()
        enc_key, hmac_key = derive_device_keys(bound_token, salt_device)

        protected_god_key_device = IntegrityVerifier.protect_data(
            god_key, enc_key, hmac_key
        )
        SecureFileHandler.write_secure(
            get_god_key_path(), salt_device + protected_god_key_device, mode=0o600
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
    with SecureString(recovery_phrase) as s_phrase:
        if not s_phrase.get():
            print(f"{Colors.BRIGHT_RED}✗ Recovery cancelled{Colors.RESET}")
            return False

        try:
            recovery_store = SecureFileHandler.read_secure(get_recovery_key_path())
            if not recovery_store:
                raise CoreException("Recovery data not found.")

            salt = recovery_store[: Config.SALT_SIZE_BYTES]
            protected_god_key = recovery_store[Config.SALT_SIZE_BYTES :]

            enc_key, hmac_key = derive_recovery_keys(s_phrase.get(), salt)

            with SecureMemory(
                IntegrityVerifier.verify_and_decrypt(
                    protected_god_key, enc_key, hmac_key
                )
            ) as god_key_mem:
                god_key = god_key_mem.get()
                new_device_token = uuid.uuid4().bytes
                salt_device = generate_salt()
                enc_key_dev, hmac_key_dev = derive_device_keys(
                    new_device_token, salt_device
                )
                protected_god_key_device = IntegrityVerifier.protect_data(
                    god_key, enc_key_dev, hmac_key_dev
                )

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

            print(f"{Colors.BRIGHT_GREEN}✓ Recovery successful!{Colors.RESET}")
            logging.info("Account recovery successful")
            return True

        except (DecryptionError, CoreException) as e:
            # Don't reset rate limiter on failure
            print(
                f"{Colors.BRIGHT_RED}✗ Recovery failed: Incorrect phrase{Colors.RESET}"
            )
            logging.error(f"Recovery failed: {e}")
            return False


def unlock_session():
    """Unlock session using device token. Returns (god_key, profiles_conn)."""
    from src.data.database import db_connect, initialize_profiles_db

    try:
        device_token = SecureFileHandler.read_secure(get_device_token_path())
        if not device_token:
            # Try recovery
            if recover_access():
                device_token = SecureFileHandler.read_secure(get_device_token_path())
            else:
                return None, None

        # VERIFY HARDWARE BINDING
        hardware_fp = get_hardware_fingerprint()
        bound_token = hashlib.sha256(device_token + hardware_fp).digest()

        key_store = SecureFileHandler.read_secure(get_god_key_path())
        if not key_store:
            raise CoreException("Key store is missing or corrupted.")

        salt = key_store[: Config.SALT_SIZE_BYTES]
        protected_god_key = key_store[Config.SALT_SIZE_BYTES :]

        # Use bound token instead of raw device token
        enc_key, hmac_key = derive_device_keys(bound_token, salt)

        try:
            raw_god_key = IntegrityVerifier.verify_and_decrypt(
                protected_god_key, enc_key, hmac_key
            )
        except CoreException:
            print(f"{Colors.BRIGHT_YELLOW}⚠ Device hardware has changed.{Colors.RESET}")
            print(f"{Colors.BRIGHT_YELLOW}   Recovery may be required.{Colors.RESET}")
            if recover_access():
                return unlock_session()
            return None, None

        session_god_key = (raw_god_key[:32], raw_god_key[32:])

    except Exception as e:
        print(f"{Colors.BRIGHT_RED}✗ Device authentication failed.{Colors.RESET}")
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
                raise CoreException("Profiles database is empty.")

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
