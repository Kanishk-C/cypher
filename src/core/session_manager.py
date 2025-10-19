"""Session timeout and auto-lock functionality."""

import time
import gc
import threading
from typing import Optional, Callable
from src.config import Config


class SessionManager:
    """Manages session timeout with immediate cleanup."""

    def __init__(
        self, on_timeout: Callable, cleanup_callback: Optional[Callable] = None
    ):
        self.timeout_seconds = Config.SESSION_TIMEOUT_SECONDS
        self.on_timeout = on_timeout
        self.cleanup_callback = cleanup_callback  # NEW
        self.last_activity = time.time()
        self._lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None
        self._active = False

    def _handle_timeout(self):
        """Checks if session timed out and triggers immediate cleanup."""
        with self._lock:
            if time.time() - self.last_activity >= self.timeout_seconds:
                if self.on_timeout:
                    self.on_timeout()

                # IMMEDIATE CLEANUP (NEW)
                if self.cleanup_callback:
                    self.cleanup_callback()

                # Force garbage collection
                for _ in range(3):
                    gc.collect()
            else:
                self._schedule_timeout()

    def start(self):
        """Starts the session timer."""
        with self._lock:
            self._active = True
            self.reset_timer()

    def reset_timer(self):
        """Resets the inactivity timer upon user activity."""
        with self._lock:
            self.last_activity = time.time()
            self._schedule_timeout()

    def _schedule_timeout(self):
        """Schedules the timeout callback."""
        if self._timer:
            self._timer.cancel()

        if self._active and self.on_timeout:
            self._timer = threading.Timer(self.timeout_seconds, self._handle_timeout)
            self._timer.daemon = True  # Allows the main program to exit
            self._timer.start()

    def stop(self):
        """Stops the session manager and cancels any pending timers."""
        with self._lock:
            self._active = False
            if self._timer:
                self._timer.cancel()
                self._timer = None
