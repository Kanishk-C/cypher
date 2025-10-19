"""Session timeout and auto-lock functionality."""

import time
import threading
from typing import Optional, Callable
from src.config import Config


class SessionManager:
    """Manages session timeout and auto-lock."""

    def __init__(self, on_timeout: Callable):
        self.timeout_seconds = Config.SESSION_TIMEOUT_SECONDS
        self.on_timeout = on_timeout
        self.last_activity = time.time()
        self._lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None
        self._active = False

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

    def _handle_timeout(self):
        """Checks if the session has truly timed out and triggers the callback."""
        with self._lock:
            # Re-check the time to avoid race conditions
            if time.time() - self.last_activity >= self.timeout_seconds:
                if self.on_timeout:
                    self.on_timeout()
            else:
                # Activity occurred just before timeout, so reschedule
                self._schedule_timeout()

    def stop(self):
        """Stops the session manager and cancels any pending timers."""
        with self._lock:
            self._active = False
            if self._timer:
                self._timer.cancel()
                self._timer = None
