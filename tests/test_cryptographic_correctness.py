class TestCryptographicCorrectness:
    """Test cryptographic implementation correctness."""

    def test_argon2_parameters(self):
        """Argon2 parameters should meet OWASP recommendations."""
        from src.config import Config

        # OWASP minimum recommendations
        assert Config.ARGON2_TIME_COST >= 2
        assert Config.ARGON2_MEMORY_COST >= 19456  # 19 MiB
        assert Config.ARGON2_PARALLELISM >= 1
        assert Config.ARGON2_SALT_LEN >= 16

    def test_key_derivation_output_length(self):
        """Key derivation should produce correct length keys."""
        pwd = b"password"
        salt = os.urandom(16)
        enc_key, hmac_key = derive_keys(pwd, salt)

        assert len(enc_key) == 32  # 256 bits
        assert len(hmac_key) == 32  # 256 bits

    def test_aes_gcm_nonce_uniqueness(self):
        """AES-GCM nonces should be unique."""
        key = os.urandom(32)
        data = b"test"

        nonces = set()
        for _ in range(100):
            encrypted = encrypt_data(data, key)
            nonce = encrypted[:12]
            assert nonce not in nonces
            nonces.add(nonce)

    def test_hmac_size(self):
        """HMAC tags should be correct size."""
        data = b"test"
        key = os.urandom(32)
        tag = IntegrityVerifier.create_hmac(data, key)

        assert len(tag) == 32  # SHA-256 output

    def test_fernet_token_format(self):
        """Fernet tokens should have correct format."""
        data = b"test"
        enc_key = os.urandom(32)
        hmac_key = os.urandom(32)

        protected = IntegrityVerifier.protect_data(data, enc_key, hmac_key)

        # Should be: Fernet(encrypted_data) + HMAC(32 bytes)
        assert len(protected) > 32
