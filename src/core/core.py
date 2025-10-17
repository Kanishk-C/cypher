"""Core session controller."""

import sqlite3
import io
import os
import logging
from datetime import datetime
from core import encryption, auth
from core.security import SecureFileHandler, IntegrityVerifier
from data import database
from exceptions import *
from interface import colors
import bcrypt


class App:
    """Manages the active, authenticated session."""

    def __init__(self, profiles_conn, session_god_key):
        self.profiles_conn = profiles_conn
        self.session_god_key = session_god_key  # (enc_key, hmac_key)
        self.profile_name: str | None = None
        self.user_db_conn: sqlite3.Connection | None = None
        self.profile_keys: tuple | None = None  # (enc_key, hmac_key)

    def load_user_profile(self, profile_name: str, master_password: str) -> bool:
        """Loads or creates a specific user profile."""
        profile_details = database.get_profile_details(self.profiles_conn, profile_name)

        if not profile_details:
            # Create new profile
            logging.info(f"Creating new profile: '{profile_name}'")
            salt = os.urandom(16)
            creation_date = datetime.utcnow().isoformat()
            password_hash = auth.hash_master_password(master_password)
            
            database.add_profile_entry(self.profiles_conn, profile_name, creation_date, salt, password_hash)
            
            self.user_db_conn = database.db_connect()
            database.initialize_user_db(self.user_db_conn)
            
            self.profile_keys = encryption.derive_profile_specific_keys(
                master_password, profile_name, creation_date, salt
            )
            self.profile_name = profile_name
            
            logging.info(f"Profile '{profile_name}' created successfully")
            return True
        else:
            # Load existing profile
            creation_date, salt, password_hash = profile_details
            
            # Verify password
            if not bcrypt.checkpw(master_password.encode("utf-8"), password_hash):
                logging.warning(f"Failed login attempt for profile: '{profile_name}'")
                return False
            
            self.profile_keys = encryption.derive_profile_specific_keys(
                master_password, profile_name, creation_date, salt
            )
            
            user_db_path = database.get_user_profile_path(profile_name)
            
            if not os.path.exists(user_db_path):
                self.user_db_conn = database.db_connect()
                database.initialize_user_db(self.user_db_conn)
            else:
                try:
                    protected_user_db = SecureFileHandler.read_secure(user_db_path)
                    decrypted_db_bytes = IntegrityVerifier.verify_and_decrypt(
                        protected_user_db,
                        self.profile_keys[0],
                        self.profile_keys[1]
                    )
                    self.user_db_conn = database.db_connect()
                    self.user_db_conn.executescript(decrypted_db_bytes.decode("utf-8"))
                except CoreException as e:
                    logging.error(f"Failed to decrypt profile '{profile_name}': {e.message}")
                    return False
            
            self.profile_name = profile_name
            logging.info(f"Profile '{profile_name}' logged in successfully")
            return True

    def is_profile_loaded(self) -> bool:
        """Checks if a user profile is currently active."""
        return self.user_db_conn is not None and self.profile_keys is not None

    def unload_profile(self):
        """Securely saves and unloads the currently active user profile."""
        if self.is_profile_loaded():
            try:
                # Dump database to string
                user_db_dump = io.StringIO()
                for line in self.user_db_conn.iterdump():
                    user_db_dump.write(f'{line}\n')
                user_db_bytes = user_db_dump.getvalue().encode('utf-8')
                
                # Encrypt with integrity protection
                protected_user_db = IntegrityVerifier.protect_data(
                    user_db_bytes,
                    self.profile_keys[0],
                    self.profile_keys[1]
                )
                
                SecureFileHandler.write_secure(
                    database.get_user_profile_path(self.profile_name),
                    protected_user_db
                )
                
                self.user_db_conn.close()
                self.user_db_conn = None
                self.profile_keys = None
                
                logging.info(f"Profile '{self.profile_name}' unloaded and saved")
                self.profile_name = None
                
            except Exception as e:
                logging.error(f"Error unloading profile: {e}")
                raise CoreException(f"Failed to save profile: {e}")

    def close_and_save_session(self):
        """Securely saves all data on exit."""
        try:
            self.unload_profile()

            # Save profiles database
            profiles_db_dump = io.StringIO()
            for line in self.profiles_conn.iterdump():
                profiles_db_dump.write(f'{line}\n')
            profiles_db_bytes = profiles_db_dump.getvalue().encode('utf-8')
            
            protected_profiles_db = IntegrityVerifier.protect_data(
                profiles_db_bytes,
                self.session_god_key[0],
                self.session_god_key[1]
            )
            
            SecureFileHandler.write_secure(
                database.get_profiles_db_path(),
                protected_profiles_db
            )
            
            self.profiles_conn.close()
            
            print(f"\n{colors.Colors.BRIGHT_GREEN}✓ Session saved securely. Goodbye!{colors.Colors.RESET}")
            logging.info("Session closed successfully")
            
        except Exception as e:
            logging.error(f"Error closing session: {e}")
            print(f"\n{colors.Colors.BRIGHT_RED}✗ Error saving session: {e}{colors.Colors.RESET}")

    def add_password(self, service, username, password, notes=""):
        """Add a new password entry."""
        if not self.is_profile_loaded():
            raise CoreException("No profile loaded.")
        
        try:
            encrypted_pass_bytes = encryption.encrypt_data(
                password.encode('utf-8'),
                self.profile_keys[0]
            )
            database.add_password_entry(self.user_db_conn, service, username, encrypted_pass_bytes, notes)
            logging.info(f"Added password for '{service}' ({username})")
            
        except sqlite3.IntegrityError:
            raise DuplicateEntryError(f"Entry for '{service}' and '{username}' already exists.")
        except sqlite3.Error as e:
            raise DatabaseError(f"Database error during add: {e}")

    def get_specific_entry(self, service, username):
        """Get a specific password entry."""
        if not self.is_profile_loaded():
            raise CoreException("No profile loaded.")
        
        try:
            record = database.get_password_entry(self.user_db_conn, service, username)
            if not record:
                raise EntryNotFoundError(f"No entry found for '{service}' and '{username}'.")
            
            password_data, notes = record
            decrypted_password_bytes = encryption.decrypt_data(password_data, self.profile_keys[0])
            
            logging.info(f"Retrieved password for '{service}' ({username})")
            return {"password": decrypted_password_bytes.decode('utf-8'), "notes": notes or ""}
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Database error during get: {e}")

    def get_entries_by_service(self, service):
        """Get all entries for a given service."""
        if not self.is_profile_loaded():
            raise CoreException("No profile loaded.")
        
        try:
            records = database.get_all_for_service(self.user_db_conn, service)
            if not records:
                raise EntryNotFoundError(f"No entries found for service '{service}'.")

            entries = []
            for username, password_data, notes in records:
                try:
                    decrypted_password = encryption.decrypt_data(
                        password_data,
                        self.profile_keys[0]
                    ).decode('utf-8')
                    entries.append({
                        "username": username,
                        "password": decrypted_password,
                        "notes": notes or ""
                    })
                except DecryptionError as e:
                    logging.warning(f"Skipping entry for '{username}': {e}")
            
            return entries
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Database error during list by service: {e}")

    def list_all_entries(self):
        """List all entries (service and username only)."""
        if not self.is_profile_loaded():
            raise CoreException("No profile loaded.")
        
        try:
            return database.get_all_entries(self.user_db_conn)
        except sqlite3.Error as e:
            raise DatabaseError(f"Database error during list all: {e}")

    def delete_password(self, service, username):
        """Delete a password entry."""
        if not self.is_profile_loaded():
            raise CoreException("No profile loaded.")
        
        try:
            changes = database.delete_password_entry(self.user_db_conn, service, username)
            if changes == 0:
                raise EntryNotFoundError(f"No entry found for '{service}' and '{username}'.")
            
            logging.info(f"Deleted password for '{service}' ({username})")
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Database error during delete: {e}")
