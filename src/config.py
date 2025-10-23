import os


class Config:
    """
    Application configuration constants.

    Environment-aware configuration that adapts between development and production.
    Set CYPHER_ENV=production for production settings.
    """

    # ============================================
    # VERSION & ENVIRONMENT
    # ============================================

    VERSION = "1.0.0"
    APP_NAME = "Cypher CLI"

    # Environment detection (defaults to PRODUCTION for safety)
    IS_PRODUCTION = os.getenv("CYPHER_ENV", "production") == "production"

    # ============================================
    # SECURITY PARAMETERS
    # ============================================

    # Password requirements
    MIN_PASSWORD_LENGTH = 8
    MIN_MASTER_PASSWORD_LENGTH = 12
    MIN_RECOVERY_PHRASE_WORDS = 12

    # Authentication rate limiting
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_TIME_SECONDS = 300  # 5 minutes

    # ============================================
    # ARGON2 KEY DERIVATION PARAMETERS
    # ============================================
    # These are environment-specific for optimal security vs. usability

    if IS_PRODUCTION:
        # PRODUCTION SETTINGS (OWASP Recommended - Strong Security)
        # These settings provide strong protection against brute force attacks
        # but may take 2-3 seconds per key derivation on typical hardware
        ARGON2_TIME_COST = 3  # Iterations (OWASP minimum: 2)
        ARGON2_MEMORY_COST = 65536  # 64 MiB (OWASP minimum: 19 MiB)
        ARGON2_PARALLELISM = 1  # Single thread (OWASP: 1)

    else:
        # DEVELOPMENT SETTINGS (Faster for Testing)
        # WARNING: These settings are NOT secure for production use
        # Use only for development and testing
        ARGON2_TIME_COST = 1  # Faster iterations
        ARGON2_MEMORY_COST = 8192  # 8 MiB (much faster)
        ARGON2_PARALLELISM = 1  # Single thread

    # Argon2 output lengths (same for both environments)
    ARGON2_KEY_LEN = 64  # 64 bytes = 512 bits (enc_key + hmac_key)
    ARGON2_PASS_HASH_LEN = 32  # 32 bytes = 256 bits for password hashes
    ARGON2_SALT_LEN = 16  # 16 bytes = 128 bits (OWASP minimum)

    # ============================================
    # CRYPTOGRAPHIC CONSTANTS
    # ============================================

    KEY_SIZE_BYTES = 32  # AES-256 key size
    SALT_SIZE_BYTES = 16  # 128-bit salt for key derivation
    HMAC_SIZE_BYTES = 32  # SHA-256 HMAC tag size

    # ============================================
    # SESSION MANAGEMENT
    # ============================================

    SESSION_TIMEOUT_SECONDS = 900  # 15 minutes of inactivity
    SESSION_TIMEOUT_WARNING_THRESHOLD = 0.8  # Warn at 80% of timeout
    SESSION_TIMEOUT_CHECK_INTERVAL = 60  # Check every 60 seconds

    # ============================================
    # INPUT VALIDATION LIMITS
    # ============================================
    # These prevent memory exhaustion and DoS attacks

    MAX_PASSWORD_LENGTH = 1000  # Maximum password length
    MAX_RECOVERY_PHRASE_LENGTH = 1000  # Maximum recovery phrase length
    MAX_SERVICE_NAME_LENGTH = 100  # Maximum service name length
    MAX_USERNAME_LENGTH = 100  # Maximum username length
    MAX_NOTES_LENGTH = 500  # Maximum notes field length
    MAX_PROFILE_NAME_LENGTH = 50  # Maximum profile name length

    # ============================================
    # FILE SECURITY
    # ============================================

    SECURE_DELETE_PASSES = 3  # Number of overwrite passes for secure deletion

    # ============================================
    # RATE LIMITING
    # ============================================

    PERSIST_RATE_LIMITS = True  # Keep rate limits across restarts
    RECOVERY_MAX_ATTEMPTS = 5  # Max recovery attempts before lockout
    RECOVERY_LOCKOUT_TIME = 3600  # 1 hour lockout for recovery

    # ============================================
    # USER INTERFACE SETTINGS
    # ============================================

    TERMINAL_MAX_WIDTH = 120  # Maximum terminal width for UI
    LOADING_DISPLAY_DURATION = 1.0  # Seconds to show loading messages
    ERROR_DISPLAY_DURATION = 2.5  # Seconds to show error messages
    SUCCESS_DISPLAY_DURATION = 1.5  # Seconds to show success messages

    # ============================================
    # FILE PATHS (relative to storage directory)
    # ============================================

    DEVICE_TOKEN_FILE = "device.token"
    GOD_KEY_FILE = "cypher.key"
    RECOVERY_KEY_FILE = "recovery.key"
    PROFILES_DB_FILE = "profiles.db.enc"
    LOG_FILE = "cypher_activity.log"
    SECURITY_AUDIT_LOG = "security_audit.log"

    # ============================================
    # FEATURE FLAGS
    # ============================================

    ENABLE_SESSION_TIMEOUT = True  # Enable automatic session timeout
    ENABLE_RATE_LIMITING = True  # Enable rate limiting
    ENABLE_SECURE_DELETE = True  # Enable secure file deletion
    ENABLE_AUDIT_LOGGING = False  # Enable security audit logging (future)

    # ============================================
    # METHODS
    # ============================================

    @classmethod
    def get_environment(cls) -> str:
        """
        Get current environment name.

        Returns:
            'production' or 'development'
        """
        return "production" if cls.IS_PRODUCTION else "development"

    @classmethod
    def get_argon2_info(cls) -> dict:
        """
        Get Argon2 configuration info for display/logging.

        Returns:
            Dictionary with Argon2 parameters
        """
        return {
            "time_cost": cls.ARGON2_TIME_COST,
            "memory_cost": cls.ARGON2_MEMORY_COST,
            "memory_mb": cls.ARGON2_MEMORY_COST // 1024,
            "parallelism": cls.ARGON2_PARALLELISM,
            "environment": cls.get_environment(),
        }

    @classmethod
    def print_config_summary(cls):
        """Print configuration summary (useful for debugging)."""
        print(f"\n{cls.APP_NAME} v{cls.VERSION}")
        print(f"Environment: {cls.get_environment().upper()}")
        print(f"\nArgon2 Parameters:")
        print(f"  Time cost: {cls.ARGON2_TIME_COST} iterations")
        print(f"  Memory: {cls.ARGON2_MEMORY_COST // 1024} MiB")
        print(f"  Parallelism: {cls.ARGON2_PARALLELISM} thread(s)")
        print(f"\nSecurity:")
        print(f"  Session timeout: {cls.SESSION_TIMEOUT_SECONDS // 60} minutes")
        print(f"  Max login attempts: {cls.MAX_LOGIN_ATTEMPTS}")
        print(
            f"  Rate limiting: {'Enabled' if cls.ENABLE_RATE_LIMITING else 'Disabled'}\n"
        )


# ============================================
# ENVIRONMENT DETECTION HELPER
# ============================================


def set_development_mode():
    """
    Force development mode (useful for testing).

    WARNING: This bypasses security settings. Never use in production.
    """
    os.environ["CYPHER_ENV"] = "development"
    # Note: Requires reimport or restart to take effect


def set_production_mode():
    """Force production mode with secure defaults."""
    os.environ["CYPHER_ENV"] = "production"
    # Note: Requires reimport or restart to take effect


# ============================================
# VALIDATION
# ============================================


def validate_config():
    """
    Validate configuration parameters meet security requirements.

    Raises:
        ValueError: If configuration is insecure
    """
    errors = []

    # Validate Argon2 parameters meet OWASP minimums
    if Config.IS_PRODUCTION:
        if Config.ARGON2_TIME_COST < 2:
            errors.append("Production time_cost must be >= 2 (OWASP minimum)")

        if Config.ARGON2_MEMORY_COST < 19456:  # 19 MiB in KiB
            errors.append("Production memory_cost must be >= 19456 KiB (OWASP minimum)")

        if Config.ARGON2_PARALLELISM < 1:
            errors.append("Parallelism must be >= 1 (OWASP minimum)")

    # Validate salt lengths
    if Config.ARGON2_SALT_LEN < 16:
        errors.append("Salt length must be >= 16 bytes (128 bits)")

    # Validate key sizes
    if Config.KEY_SIZE_BYTES < 32:
        errors.append("Encryption key size must be >= 32 bytes (256 bits)")

    # Validate session timeout
    if Config.SESSION_TIMEOUT_SECONDS < 60:
        errors.append("Session timeout too short (minimum 60 seconds)")

    if errors:
        raise ValueError(
            f"Configuration validation failed:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )


# Run validation on import
try:
    validate_config()
except ValueError as e:
    import logging

    logging.warning(f"Configuration validation warning: {e}")


# ============================================
# USAGE EXAMPLES (for documentation)
# ============================================

if __name__ == "__main__":
    """
    Example usage of Config class.

    Run this file directly to see configuration summary.
    """
    Config.print_config_summary()

    print("Configuration validation:", end=" ")
    try:
        validate_config()
        print("✓ PASSED")
    except ValueError as e:
        print(f"✗ FAILED\n{e}")
