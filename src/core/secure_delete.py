"""Secure file deletion with overwrite."""

import os
import secrets
import logging
from src.config import Config


class SecureDelete:
    """Securely delete files by overwriting before deletion."""

    @staticmethod
    def secure_delete_file(filepath: str, passes: int = None):
        """
        Securely delete a file by overwriting it multiple times.

        Args:
            filepath: Path to the file to delete.
            passes: Number of overwrite passes (defaults to value in config).
        """
        if not os.path.exists(filepath):
            return

        passes = passes or Config.SECURE_DELETE_PASSES

        try:
            file_size = os.path.getsize(filepath)
            # Open in binary write mode and overwrite
            with open(filepath, "rb+") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            # Finally, delete the file's reference
            os.unlink(filepath)
        except Exception as e:
            logging.error(f"Secure delete failed for {filepath}: {e}")
            # As a fallback, attempt a regular deletion
            try:
                os.unlink(filepath)
            except OSError:
                pass
