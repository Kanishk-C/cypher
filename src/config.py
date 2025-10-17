class Config:
    """Application configuration constants."""
    
    # Security - ENHANCED ITERATIONS
    MIN_PASSWORD_LENGTH = 8
    MIN_MASTER_PASSWORD_LENGTH = 12
    MIN_RECOVERY_PHRASE_WORDS = 12
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_TIME_SECONDS = 300
    SESSION_TIMEOUT_MINUTES = 15
    
    # Cryptography - INCREASED ITERATIONS (2025 recommendations)
    PBKDF2_ITERATIONS_DEVICE = 200000      # Increased from 100k
    PBKDF2_ITERATIONS_PROFILE = 600000     # Increased from 250k
    PBKDF2_ITERATIONS_RECOVERY = 700000    # Increased from 350k
    KEY_SIZE_BYTES = 32
    SALT_SIZE_BYTES = 16
    HMAC_SIZE_BYTES = 32
    
    # Fernet timestamp validation
    FERNET_TTL_SECONDS = None  # None = no expiry, or set to 86400 for 24h
    
    # Database
    MAX_SERVICE_NAME_LENGTH = 100
    MAX_USERNAME_LENGTH = 255
    MAX_NOTES_LENGTH = 1000
    
    # UI
    TERMINAL_MIN_WIDTH = 60
    TERMINAL_MAX_WIDTH = 120
    RECENT_ENTRIES_LIMIT = 5
    
    # File paths
    DEVICE_TOKEN_FILE = "device.token"
    GOD_KEY_FILE = "cypher.key"
    RECOVERY_KEY_FILE = "recovery.key"
    PROFILES_DB_FILE = "profiles.db.enc"
    LOG_FILE = "cypher_activity.log"
    SECURITY_AUDIT_LOG = "security_audit.log"
