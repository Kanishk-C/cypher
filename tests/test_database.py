import pytest
import os
import sqlite3
from src.data.database import *


class TestDatabasePaths:
    """Test database path functions."""

    def test_storage_directory_created(self):
        """Storage directory should be created if not exists."""
        storage_dir = get_storage_directory()
        assert os.path.exists(storage_dir)
        assert os.path.isdir(storage_dir)

    def test_profile_path_sanitization(self):
        """Profile paths should be sanitized."""
        # Test dangerous inputs
        dangerous_names = [
            "../../../etc/passwd",
            "../../.ssh/id_rsa",
            "test/../../escape",
            "test\x00null",
            "con.txt",  # Windows reserved
        ]

        storage = get_storage_directory()
        for name in dangerous_names:
            path = get_user_profile_path(name)
            # Path should be inside storage directory
            assert path.startswith(storage)
            # Should not contain path traversal
            assert ".." not in path


class TestDatabaseOperations:
    """Test database CRUD operations."""

    @pytest.fixture
    def test_db(self):
        """Create a test database."""
        conn = db_connect()
        initialize_user_db(conn)
        yield conn
        conn.close()

    def test_add_password_entry(self, test_db):
        """Should add password entry successfully."""
        add_password_entry(test_db, "github", "user@example.com", b"encrypted", "notes")

        result = get_password_entry(test_db, "github", "user@example.com")
        assert result is not None
        assert result[0] == b"encrypted"
        assert result[1] == "notes"

    def test_add_duplicate_entry_fails(self, test_db):
        """Adding duplicate entry should raise IntegrityError."""
        add_password_entry(test_db, "github", "user@example.com", b"enc1", "")

        with pytest.raises(sqlite3.IntegrityError):
            add_password_entry(test_db, "github", "user@example.com", b"enc2", "")

    def test_get_nonexistent_entry(self, test_db):
        """Getting nonexistent entry should return None."""
        result = get_password_entry(test_db, "nonexistent", "user")
        assert result is None

    def test_delete_entry(self, test_db):
        """Should delete entry successfully."""
        add_password_entry(test_db, "github", "user@example.com", b"enc", "")

        changes = delete_password_entry(test_db, "github", "user@example.com")
        assert changes == 1

        result = get_password_entry(test_db, "github", "user@example.com")
        assert result is None

    def test_get_all_for_service(self, test_db):
        """Should retrieve all entries for a service."""
        add_password_entry(test_db, "github", "user1@example.com", b"enc1", "")
        add_password_entry(test_db, "github", "user2@example.com", b"enc2", "")
        add_password_entry(test_db, "gitlab", "user3@example.com", b"enc3", "")

        results = get_all_for_service(test_db, "github")
        assert len(results) == 2

    def test_sql_injection_prevention(self, test_db):
        """SQL injection attempts should be prevented."""
        # Attempt SQL injection in service name
        malicious_service = "'; DROP TABLE passwords; --"
        add_password_entry(test_db, malicious_service, "user", b"enc", "")

        # Table should still exist
        result = get_all_entries(test_db)
        assert isinstance(result, list)
