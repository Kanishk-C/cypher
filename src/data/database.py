"""Handles all database interactions and secure file management."""

import sqlite3
import os

# --- Path Management ---


def get_storage_directory():
    """Ensures and returns the application's storage directory path."""
    storage_dir = os.path.join(os.path.expanduser("~"), ".cypher")
    os.makedirs(storage_dir, exist_ok=True)
    return storage_dir


def get_god_key_store_path():
    """Returns the path to the encrypted God Key store."""
    return os.path.join(get_storage_directory(), "cypher.key")


def get_recovery_store_path():
    """Returns the path to the recovery-encrypted God Key store."""
    return os.path.join(get_storage_directory(), "recovery.key")


def get_profiles_db_path():
    """Returns the path to the encrypted central profiles database."""
    return os.path.join(get_storage_directory(), "profiles.db.enc")


def get_user_profile_path(profile_name: str):
    """Constructs the full, safe path for a user's encrypted profile database."""
    storage_dir = get_storage_directory()
    safe_filename = "".join(c for c in profile_name if c.isalnum() or c in ("_", "-"))
    return os.path.join(storage_dir, f"{safe_filename}.db.enc")


def get_device_token_path():
    """Returns the path to the device token file."""
    return os.path.join(get_storage_directory(), "device.token")


# --- Setup & File Management ---


def is_first_ever_run():
    """Checks if the God Key store exists to determine if this is the first run."""
    return not os.path.exists(get_god_key_store_path())


# --- Database Initialization ---


def db_connect(db_path=":memory:"):
    """Establishes a connection, defaulting to an in-memory database."""
    return sqlite3.connect(db_path)


def initialize_profiles_db(conn):
    """Initializes the central profiles table."""
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS profiles(
            profile_name TEXT PRIMARY KEY,
            creation_date TEXT NOT NULL,
            salt BLOB NOT NULL,
            password_hash BLOB NOT NULL
        );
        """
    )
    conn.commit()


def initialize_user_db(conn):
    """Initializes the tables for an individual user's password vault."""
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS passwords(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password_data BLOB NOT NULL,
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT unique_service_username UNIQUE (service, username)
        );
        """
    )
    conn.commit()


# --- Profile DB CRUD Operations ---


def add_profile_entry(conn, profile_name, creation_date, salt, password_hash):
    """Adds a new profile's metadata to the central profiles database."""
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO profiles (profile_name, creation_date, salt, password_hash) VALUES (?, ?, ?, ?)",
        (profile_name, creation_date, salt, password_hash),
    )
    conn.commit()


def get_profile_details(conn, profile_name):
    """Retrieves a specific profile's metadata from the central profiles database."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT creation_date, salt, password_hash FROM profiles WHERE profile_name = ?",
        (profile_name,),
    )
    return cursor.fetchone()


def get_all_profile_names(conn):
    """Retrieves all profile names from the central profiles database."""
    cursor = conn.cursor()
    cursor.execute("SELECT profile_name FROM profiles ORDER BY profile_name")
    return [row[0] for row in cursor.fetchall()]


# --- User Password CRUD Operations ---


def add_password_entry(conn, service, username, encrypted_password, notes):
    """Adds a password entry to the database."""
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO passwords (service, username, password_data, notes) VALUES (?, ?, ?, ?)",
        (service, username, encrypted_password, notes),
    )
    conn.commit()


def delete_password_entry(conn, service, username):
    """Deletes a password entry from the database."""
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM passwords WHERE service = ? AND username = ?",
        (service, username),
    )
    changes = cursor.rowcount
    conn.commit()
    return changes


def get_password_entry(conn, service, username):
    """Gets a specific password entry."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_data, notes FROM passwords WHERE service = ? AND username = ?",
        (service, username),
    )
    return cursor.fetchone()


def get_all_for_service(conn, service):
    """Retrieves all entries for a given service."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, password_data, notes FROM passwords WHERE service = ?",
        (service,),
    )
    return cursor.fetchall()


def get_all_entries(conn):
    """Gets all entries (service and username only)."""
    cursor = conn.cursor()
    cursor.execute("SELECT service, username FROM passwords ORDER BY service")
    return cursor.fetchall()
