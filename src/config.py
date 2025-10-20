import os


class Config:
    """Application configuration constants."""

    IS_PRODUCTION = os.getenv("CYPHER_ENV", "development") == "production"

    # Security Parameters
    MIN_PASSWORD_LENGTH = 8
    MIN_MASTER_PASSWORD_LENGTH = 12
    MIN_RECOVERY_PHRASE_WORDS = 12
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_TIME_SECONDS = 300

    # Argon2 Parameters - OPTIMIZED FOR DEVELOPMENT/TESTING
    # For production, increase memory_cost to 65536 or higher
    ARGON2_TIME_COST = 2  # Iterations
    ARGON2_MEMORY_COST = 65536  # Production: 64 MiB
    ARGON2_PARALLELISM = 1  # Single thread
    ARGON2_KEY_LEN = 64  # Output length
    ARGON2_PASS_HASH_LEN = 32  # Hash length
    ARGON2_SALT_LEN = 16  # Salt length

    # Crypto
    KEY_SIZE_BYTES = 32
    SALT_SIZE_BYTES = 16
    HMAC_SIZE_BYTES = 32

    # Session Management
    SESSION_TIMEOUT_SECONDS = 900  # 15 minutes

    # Input Limits
    MAX_PASSWORD_LENGTH = 1000
    MAX_RECOVERY_PHRASE_LENGTH = 1000
    MAX_SERVICE_NAME_LENGTH = 100
    MAX_USERNAME_LENGTH = 100
    MAX_NOTES_LENGTH = 500

    # File Security
    SECURE_DELETE_PASSES = 3

    # Rate Limiting
    PERSIST_RATE_LIMITS = True

    # UI Settings
    TERMINAL_MAX_WIDTH = 120

    # File paths
    DEVICE_TOKEN_FILE = "device.token"
    GOD_KEY_FILE = "cypher.key"
    RECOVERY_KEY_FILE = "recovery.key"
    PROFILES_DB_FILE = "profiles.db.enc"
    LOG_FILE = "cypher_activity.log"
    SECURITY_AUDIT_LOG = "security_audit.log"

    MAX_PROFILE_NAME_LENGTH = 50
    SESSION_TIMEOUT_WARNING_THRESHOLD = 0.8
    SESSION_TIMEOUT_CHECK_INTERVAL = 60
    LOADING_DISPLAY_DURATION = 1.0
    ERROR_DISPLAY_DURATION = 2.5
    SUCCESS_DISPLAY_DURATION = 1.5
    RECOVERY_MAX_ATTEMPTS = 5
    RECOVERY_LOCKOUT_TIME = 3600
