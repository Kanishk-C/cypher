class Config:
    """Application configuration constants."""

    # Security Parameters
    MIN_PASSWORD_LENGTH = 8
    MIN_MASTER_PASSWORD_LENGTH = 12
    MIN_RECOVERY_PHRASE_WORDS = 12
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_TIME_SECONDS = 300

    # Argon2 Parameters
    ARGON2_TIME_COST = 2
    ARGON2_MEMORY_COST = 19456
    ARGON2_PARALLELISM = 1
    ARGON2_KEY_LEN = 64
    ARGON2_PASS_HASH_LEN = 32
    ARGON2_SALT_LEN = 16

    # Crypto
    KEY_SIZE_BYTES = 32
    SALT_SIZE_BYTES = 16
    HMAC_SIZE_BYTES = 32

    # Session Management (NEW)
    SESSION_TIMEOUT_SECONDS = 900  # 15 minutes

    # Input Limits (NEW)
    MAX_PASSWORD_LENGTH = 1000
    MAX_RECOVERY_PHRASE_LENGTH = 1000

    # File Security (NEW)
    SECURE_DELETE_PASSES = 3

    # Rate Limiting (NEW)
    PERSIST_RATE_LIMITS = True

    # File paths
    DEVICE_TOKEN_FILE = "device.token"
    GOD_KEY_FILE = "cypher.key"
    RECOVERY_KEY_FILE = "recovery.key"
    PROFILES_DB_FILE = "profiles.db.enc"
    LOG_FILE = "cypher_activity.log"
    SECURITY_AUDIT_LOG = "security_audit.log"
