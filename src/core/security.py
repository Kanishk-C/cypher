"""Enhanced security utilities with additional protections."""

import os
import stat
import hmac
import hashlib
import secrets
import time
import logging
import gc
import base64
from typing import Optional, Tuple
from cryptography.fernet import Fernet, InvalidToken
from exceptions import CoreException
from config import Config


class SecureFileHandler:
    """Handles secure file operations with proper permissions."""
    
    @staticmethod
    def write_secure(path: str, data: bytes, mode: int = 0o600):
        """Write data to file with secure permissions atomically."""
        temp_path = path + '.tmp'
        try:
            with open(temp_path, 'wb') as f:
                f.write(data)
            
            if hasattr(os, 'chmod'):
                os.chmod(temp_path, mode)
            
            if os.path.exists(path):
                os.replace(temp_path, path)
            else:
                os.rename(temp_path, path)
                
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
            raise CoreException(f"Secure write failed: {e}")
    
    @staticmethod
    def read_secure(path: str, check_permissions: bool = True) -> Optional[bytes]:
        """Read data from file and optionally verify permissions."""
        if not os.path.exists(path):
            return None
        
        if check_permissions and hasattr(os, 'stat') and hasattr(stat, 'S_IMODE'):
            try:
                st = os.stat(path)
                mode = stat.S_IMODE(st.st_mode)
                if mode & 0o077:
                    logging.warning(f"Insecure file permissions on {path}: {oct(mode)}")
            except Exception as e:
                logging.warning(f"Could not check permissions on {path}: {e}")
        
        try:
            with open(path, 'rb') as f:
                return f.read()
        except Exception as e:
            raise CoreException(f"Failed to read {path}: {e}")


class SecureMemory:
    """Wrapper for sensitive data that clears on deletion."""
    
    def __init__(self, data: bytes):
        self._data = bytearray(data)
        self._cleared = False
    
    def get(self) -> bytes:
        """Get the data as bytes."""
        if self._cleared:
            raise CoreException("Attempting to access cleared secure memory")
        return bytes(self._data)
    
    def clear(self):
        """Explicitly clear the data."""
        if not self._cleared and hasattr(self, '_data'):
            # Overwrite with random data multiple times
            for _ in range(3):
                for i in range(len(self._data)):
                    self._data[i] = secrets.randbits(8)
            self._data.clear()
            self._cleared = True
            # Force garbage collection
            gc.collect()
    
    def __del__(self):
        """Securely clear data from memory."""
        self.clear()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()


class RateLimiter:
    """Prevents brute force attacks with exponential backoff."""
    
    def __init__(self, max_attempts: int = None, lockout_time: int = None):
        self.max_attempts = max_attempts or Config.MAX_LOGIN_ATTEMPTS
        self.lockout_time = lockout_time or Config.LOCKOUT_TIME_SECONDS
        self.attempts = {}
    
    def check_attempt(self, identifier: str) -> Tuple[bool, int]:
        """
        Check if attempt is allowed.
        Returns: (allowed: bool, wait_seconds: int)
        """
        now = time.time()
        
        if identifier not in self.attempts:
            self.attempts[identifier] = []
        
        # Remove old attempts
        self.attempts[identifier] = [
            t for t in self.attempts[identifier] 
            if now - t < self.lockout_time
        ]
        
        if len(self.attempts[identifier]) >= self.max_attempts:
            oldest_attempt = min(self.attempts[identifier])
            wait_time = int(self.lockout_time - (now - oldest_attempt))
            return False, max(0, wait_time)
        
        self.attempts[identifier].append(now)
        return True, 0
    
    def reset(self, identifier: str):
        """Reset attempts for successful login."""
        if identifier in self.attempts:
            del self.attempts[identifier]


class IntegrityVerifier:
    """Provides HMAC-based integrity verification with timestamp checking."""
    
    @staticmethod
    def create_hmac(data: bytes, key: bytes) -> bytes:
        """Create HMAC-SHA256 tag for data."""
        return hmac.new(key, data, hashlib.sha256).digest()
    
    @staticmethod
    def verify_hmac(data: bytes, tag: bytes, key: bytes) -> bool:
        """Verify HMAC tag with timing-attack resistance."""
        expected = IntegrityVerifier.create_hmac(data, key)
        return hmac.compare_digest(tag, expected)
    
    @staticmethod
    def protect_data(data: bytes, enc_key: bytes, hmac_key: bytes) -> bytes:
        """Encrypt data and append HMAC tag (Encrypt-then-MAC)."""
        # Fernet requires a URL-safe base64-encoded 32-byte key.
        b64_enc_key = base64.urlsafe_b64encode(enc_key)
        encrypted = Fernet(b64_enc_key).encrypt(data)
        tag = IntegrityVerifier.create_hmac(encrypted, hmac_key)
        return encrypted + tag
    
    @staticmethod
    def verify_and_decrypt(data: bytes, enc_key: bytes, hmac_key: bytes, 
                          ttl: int = None) -> bytes:
        """Verify HMAC and decrypt data with optional timestamp verification."""
        if len(data) < Config.HMAC_SIZE_BYTES:
            raise CoreException("Invalid encrypted data: too short")
        
        encrypted = data[:-Config.HMAC_SIZE_BYTES]
        tag = data[-Config.HMAC_SIZE_BYTES:]
        
        if not IntegrityVerifier.verify_hmac(encrypted, tag, hmac_key):
            raise CoreException("Integrity verification failed - data may be tampered")
        
        try:
            # Fernet requires a URL-safe base64-encoded 32-byte key.
            b64_enc_key = base64.urlsafe_b64encode(enc_key)
            fernet = Fernet(b64_enc_key)
            # If ttl is specified, Fernet will verify timestamp
            if ttl is not None:
                return fernet.decrypt(encrypted, ttl=ttl)
            else:
                return fernet.decrypt(encrypted)
        except InvalidToken as e:
            if "expired" in str(e).lower():
                raise CoreException("Encrypted data has expired")
            raise CoreException(f"Decryption failed: {e}")


class SecurityAuditor:
    """Logs security-relevant events for forensic analysis."""
    
    def __init__(self, log_path: str):
        self.log_path = log_path
        self._setup_audit_log()
    
    def _setup_audit_log(self):
        """Setup separate audit log with strict permissions."""
        audit_logger = logging.getLogger('security_audit')
        audit_logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(self.log_path, mode='a')
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - AUDIT - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        audit_logger.addHandler(handler)
        
        self.logger = audit_logger
        
        # Set strict permissions
        if hasattr(os, 'chmod'):
            try:
                os.chmod(self.log_path, 0o600)
            except:
                pass
    
    def log_crypto_operation(self, operation: str, success: bool, details: str = ""):
        """Log cryptographic operations."""
        status = "SUCCESS" if success else "FAILURE"
        self.logger.info(f"CRYPTO_{operation.upper()} - {status} - {details}")
    
    def log_authentication(self, profile: str, success: bool, ip: str = "local"):
        """Log authentication attempts."""
        status = "SUCCESS" if success else "FAILURE"
        self.logger.info(f"AUTH_{status} - Profile: {profile} - IP: {ip}")
    
    def log_access(self, profile: str, action: str, resource: str):
        """Log data access."""
        self.logger.info(f"ACCESS - Profile: {profile} - Action: {action} - Resource: {resource}")
    
    def log_security_event(self, event_type: str, details: str):
        """Log general security events."""
        self.logger.info(f"SECURITY_{event_type.upper()} - {details}")