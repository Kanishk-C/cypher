"""Core application session and profile management."""

import sqlite3
import io
import os
import logging
from datetime import datetime
from src.core.crypto import (
    hash_password,
    verify_password,
    generate_salt,
    derive_profile_keys,
    encrypt_data,
    decrypt_data,
    IntegrityVerifier,
    SecureFileHandler,
)
from src.data import database
from src.exceptions import (
    CoreException,
    EntryNotFoundError,
    DuplicateEntryError,
    DatabaseError,
    DecryptionError,
)
from src.ui.colors import Colors


class App:
    """Manages the active authenticated session."""

    def __init__(self, profiles_conn, session_god_key):
        self.profiles_conn = profiles_conn
        self.session_god_key = session_god_key  # (enc_key, hmac_key)
        self.profile_name: str | None = None
        self.user_db_conn: sqlite3.Connection | None = None
        self.profile_keys: tuple | None = None  # (enc_key, hmac_key)

    def load_user_profile(self, profile_name: str, master_password: str) -> bool:
        """Load or create a user profile."""
        profile_details = database.get_profile_details(self.profiles_conn, profile_name)

        if not profile_details:
            # Create new profile
            logging.info(f"Creating new profile: '{profile_name}'")
            salt = generate_salt()
            creation_date = datetime.utcnow().isoformat()
            password_hash = hash_password(master_password)

            database.add_profile_entry(
                self.profiles_conn, profile_name, creation_date, salt, password_hash
            )

            self.user_db_conn = database.db_connect()
            database.initialize_user_db(self.user_db_conn)

            self.profile_keys = derive_profile_keys(
                master_password, profile_name, creation_date, salt
            )
            self.profile_name = profile_name

            logging.info(f"Profile '{profile_name}' created successfully")
            return True
        else:
            # Load existing profile
            creation_date, salt, password_hash = profile_details

            if not verify_password(password_hash, master_password):
                logging.warning(f"Failed login attempt for profile: '{profile_name}'")
                return False

            self.profile_keys = derive_profile_keys(
                master_password, profile_name, creation_date, salt
            )

            user_db_path = database.get_user_profile_path(profile_name)

            if not os.path.exists(user_db_path):
                # No existing profile DB file, initialize a new one
                self.user_db_conn = database.db_connect()
                database.initialize_user_db(self.user_db_conn)
            else:
                try:
                    protected_db = SecureFileHandler.read_secure(user_db_path)
                    if protected_db is None:
                        # Unable to read file - treat as fresh DB
                        self.user_db_conn = database.db_connect()
                        database.initialize_user_db(self.user_db_conn)
                    else:
                        # At this point profile_keys is set above, so narrow types
                        assert self.profile_keys is not None
                        decrypted = IntegrityVerifier.verify_and_decrypt(
                            protected_db, self.profile_keys[0], self.profile_keys[1]
                        )
                        self.user_db_conn = database.db_connect()
                        self.user_db_conn.executescript(decrypted.decode("utf-8"))
                except CoreException:
                    logging.error(f"Failed to decrypt profile '{profile_name}'")
                    return False

            self.profile_name = profile_name
            logging.info(f"Profile '{profile_name}' logged in successfully")
            return True

    def is_profile_loaded(self) -> bool:
        """Check if a user profile is active."""
        return self.user_db_conn is not None and self.profile_keys is not None

    def unload_profile(self):
        """Save and unload the current user profile."""
        if self.is_profile_loaded():
            try:
                # Narrow optionals for the type checker
                assert (
                    self.user_db_conn is not None
                    and self.profile_keys is not None
                    and self.profile_name is not None
                )
                user_db_conn = self.user_db_conn
                profile_keys = self.profile_keys
                profile_name = self.profile_name

                db_dump = io.StringIO()
                for line in user_db_conn.iterdump():
                    db_dump.write(f"{line}\n")
                db_bytes = db_dump.getvalue().encode("utf-8")

                protected_db = IntegrityVerifier.protect_data(
                    db_bytes, profile_keys[0], profile_keys[1]
                )

                SecureFileHandler.write_secure(
                    database.get_user_profile_path(profile_name), protected_db
                )

                user_db_conn.close()
                self.user_db_conn = None
                self.profile_keys = None

                logging.info(f"Profile '{profile_name}' unloaded and saved")
                self.profile_name = None

            except Exception as e:
                logging.error(f"Error unloading profile: {e}")
                raise CoreException(f"Failed to save profile: {e}")

    def close_and_save_session(self):
        """Save all data on exit."""
        try:
            self.unload_profile()

            # Save profiles database
            # Narrow type for profiles_conn
            profiles_conn = self.profiles_conn
            db_dump = io.StringIO()
            for line in profiles_conn.iterdump():
                db_dump.write(f"{line}\n")
            db_bytes = db_dump.getvalue().encode("utf-8")

            protected_db = IntegrityVerifier.protect_data(
                db_bytes, self.session_god_key[0], self.session_god_key[1]
            )

            SecureFileHandler.write_secure(
                database.get_profiles_db_path(), protected_db
            )

            profiles_conn.close()

            print(
                f"\n{Colors.BRIGHT_GREEN}✓ Session saved securely. Goodbye!{Colors.RESET}"
            )
            logging.info("Session closed successfully")

        except Exception as e:
            logging.error(f"Error closing session: {e}")
            print(f"\n{Colors.BRIGHT_RED}✗ Error saving session: {e}{Colors.RESET}")

    def add_password(self, service, username, password, notes=""):
        """Add a new password entry."""
        if not self.is_profile_loaded():
            raise CoreException("No profile loaded.")

        try:
            # Narrow optionals for type checker
            assert self.user_db_conn is not None and self.profile_keys is not None
            user_db_conn = self.user_db_conn
            profile_keys = self.profile_keys

            encrypted = encrypt_data(password.encode("utf-8"), profile_keys[0])
            database.add_password_entry(
                user_db_conn, service, username, encrypted, notes
            )
            logging.info(f"Added password for '{service}' ({username})")
        except sqlite3.IntegrityError:
            raise DuplicateEntryError(
                f"Entry for '{service}' and '{username}' already exists."
            )
        except sqlite3.Error as e:
            raise DatabaseError(f"Database error: {e}")

    def get_specific_entry(self, service, username):
        """Get a specific password entry."""
        if not self.is_profile_loaded():
            raise CoreException("No profile loaded.")

        try:
            assert self.user_db_conn is not None and self.profile_keys is not None
            user_db_conn = self.user_db_conn
            profile_keys = self.profile_keys

            record = database.get_password_entry(user_db_conn, service, username)
            if not record:
                raise EntryNotFoundError(
                    f"No entry found for '{service}' and '{username}'."
                )

            password_data, notes = record
            decrypted = decrypt_data(password_data, profile_keys[0])

            logging.info(f"Retrieved password for '{service}' ({username})")
            return {"password": decrypted.decode("utf-8"), "notes": notes or ""}
        except sqlite3.Error as e:
            raise DatabaseError(f"Database error: {e}")

    def get_entries_by_service(self, service):
        """Get all entries for a service."""
        if not self.is_profile_loaded():
            raise CoreException("No profile loaded.")

        try:
            assert self.user_db_conn is not None and self.profile_keys is not None
            user_db_conn = self.user_db_conn
            profile_keys = self.profile_keys

            records = database.get_all_for_service(user_db_conn, service)
            if not records:
                raise EntryNotFoundError(f"No entries found for service '{service}'.")

            entries = []
            for username, password_data, notes in records:
                try:
                    decrypted = decrypt_data(password_data, profile_keys[0]).decode(
                        "utf-8"
                    )
                    entries.append(
                        {
                            "username": username,
                            "password": decrypted,
                            "notes": notes or "",
                        }
                    )
                except DecryptionError as e:
                    logging.warning(f"Skipping entry for '{username}': {e}")

            return entries
        except sqlite3.Error as e:
            raise DatabaseError(f"Database error: {e}")

    def list_all_entries(self):
        """List all entries (service and username only)."""
        if not self.is_profile_loaded():
            raise CoreException("No profile loaded.")

        try:
            assert self.user_db_conn is not None
            return database.get_all_entries(self.user_db_conn)
        except sqlite3.Error as e:
            raise DatabaseError(f"Database error: {e}")

    def delete_password(self, service, username):
        """Delete a password entry."""
        if not self.is_profile_loaded():
            raise CoreException("No profile loaded.")

        try:
            assert self.user_db_conn is not None
            changes = database.delete_password_entry(
                self.user_db_conn, service, username
            )
            if changes == 0:
                raise EntryNotFoundError(
                    f"No entry found for '{service}' and '{username}'."
                )

            logging.info(f"Deleted password for '{service}' ({username})")
        except sqlite3.Error as e:
            raise DatabaseError(f"Database error: {e}")
