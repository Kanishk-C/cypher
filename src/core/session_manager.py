"""Session timeout and auto-lock functionality - FIXED."""

import time
import gc
import threading
from typing import Optional, Callable
from src.config import Config


class SessionManager:
    """Manages session timeout with immediate cleanup - FIXED VERSION."""

    def __init__(
        self, on_timeout: Callable, cleanup_callback: Optional[Callable] = None
    ):
        self.timeout_seconds = Config.SESSION_TIMEOUT_SECONDS
        self.on_timeout = on_timeout
        self.cleanup_callback = cleanup_callback
        self.last_activity = time.time()
        self._lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None
        self._active = False
        self._stop_event = threading.Event()  # ADDED: Event to signal stop

    def _handle_timeout(self):
        """Checks if session timed out and triggers immediate cleanup."""
        with self._lock:
            if not self._active:  # ADDED: Check if still active
                return

            if time.time() - self.last_activity >= self.timeout_seconds:
                if self.on_timeout:
                    try:
                        self.on_timeout()
                    except Exception:
                        pass  # Ignore errors in callback

                # IMMEDIATE CLEANUP
                if self.cleanup_callback:
                    try:
                        self.cleanup_callback()
                    except Exception:
                        pass  # Ignore errors in cleanup

                # Force garbage collection
                for _ in range(3):
                    gc.collect()
            else:
                # Activity occurred, reschedule
                if self._active:  # ADDED: Only reschedule if still active
                    self._schedule_timeout()

    def start(self):
        """Starts the session timer - NON-BLOCKING."""
        with self._lock:
            self._active = True
            self._stop_event.clear()
            self.last_activity = time.time()
            self._schedule_timeout()

    def reset_timer(self):
        """Resets the inactivity timer upon user activity."""
        with self._lock:
            if not self._active:  # ADDED: Don't reset if stopped
                return
            self.last_activity = time.time()
            # Don't reschedule on every reset - let existing timer continue

    def _schedule_timeout(self):
        """Schedules the timeout callback - NON-BLOCKING."""
        with self._lock:
            # Cancel existing timer
            if self._timer is not None:
                try:
                    self._timer.cancel()
                except Exception:
                    pass

            # Only schedule if active
            if self._active and self.on_timeout:
                try:
                    self._timer = threading.Timer(
                        self.timeout_seconds, self._handle_timeout
                    )
                    self._timer.daemon = (
                        True  # CRITICAL: Daemon thread won't block exit
                    )
                    self._timer.start()
                except Exception:
                    # If timer creation fails, just continue without it
                    self._timer = None

    def stop(self):
        """Stops the session manager and cancels any pending timers."""
        with self._lock:
            self._active = False
            self._stop_event.set()

            if self._timer is not None:
                try:
                    self._timer.cancel()
                    self._timer = None
                except Exception:
                    pass  # Ignore errors during cleanup
