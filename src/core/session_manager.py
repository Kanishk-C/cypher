import time
import gc
import threading
from typing import Optional, Callable
from src.config import Config
from ui.colors import Colors


class SessionManager:
    """Manages session timeout with NON-BLOCKING behavior - FIXED VERSION."""

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
        self._checking = False  # NEW: Prevent re-entrant checks

    def _handle_timeout(self):
        """Checks if session timed out - NON-BLOCKING."""
        with self._lock:
            # Guard: Don't run if already checking or inactive
            if not self._active or self._checking:
                return

            self._checking = True

        try:
            # Check timeout WITHOUT holding lock (allows activity updates)
            current_time = time.time()
            time_since_activity = current_time - self.last_activity

            if time_since_activity >= self.timeout_seconds:
                # Timeout occurred - trigger callback
                with self._lock:
                    if not self._active:  # Double-check still active
                        return

                # Execute timeout callback (non-blocking)
                if self.on_timeout:
                    try:
                        self.on_timeout()
                    except Exception:
                        pass  # Ignore callback errors

                # Cleanup
                if self.cleanup_callback:
                    try:
                        self.cleanup_callback()
                    except Exception:
                        pass

                # Force garbage collection
                for _ in range(3):
                    gc.collect()
            else:
                # Not timed out yet - reschedule check
                with self._lock:
                    if self._active:
                        self._schedule_timeout()
        finally:
            with self._lock:
                self._checking = False

    def _handle_timeout_with_warning(self):
        """Enhanced timeout handler with warning."""
        with self._lock:
            if not self._active or self._checking:
                return
            self._checking = True

        try:
            current_time = time.time()
            time_since_activity = current_time - self.last_activity

            # Warning at 80% of timeout
            warning_threshold = self.timeout_seconds * 0.8

            if time_since_activity >= self.timeout_seconds:
                # Actual timeout
                if self.on_timeout:
                    try:
                        self.on_timeout()
                    except Exception:
                        pass

                if self.cleanup_callback:
                    try:
                        self.cleanup_callback()
                    except Exception:
                        pass

                for _ in range(3):
                    gc.collect()

            elif time_since_activity >= warning_threshold:
                # Show warning (non-blocking)
                remaining = int(self.timeout_seconds - time_since_activity)
                print(
                    f"\n{Colors.BRIGHT_YELLOW}⚠ Warning: Session will timeout "
                    f"in {remaining} seconds{Colors.RESET}"
                )
                # Reschedule
                with self._lock:
                    if self._active:
                        self._schedule_timeout()
            else:
                # Normal reschedule
                with self._lock:
                    if self._active:
                        self._schedule_timeout()
        finally:
            with self._lock:
                self._checking = False

    def start(self):
        """Starts the session timer - COMPLETELY NON-BLOCKING."""
        with self._lock:
            self._active = True
            self.last_activity = time.time()
            self._schedule_timeout()

    def reset_timer(self):
        """Resets the inactivity timer - LIGHTWEIGHT operation."""
        with self._lock:
            if not self._active:
                return
            self.last_activity = time.time()
            # Don't reschedule here - let existing timer continue

    def _schedule_timeout(self):
        """Schedules the timeout callback - GUARANTEED NON-BLOCKING."""
        # Cancel existing timer
        if self._timer is not None:
            try:
                self._timer.cancel()
            except Exception:
                pass

        # Schedule new timer ONLY if active
        if self._active and self.on_timeout:
            try:
                self._timer = threading.Timer(
                    self.timeout_seconds, self._handle_timeout
                )
                self._timer.daemon = True  # CRITICAL: Daemon thread won't block exit
                self._timer.start()
            except Exception:
                # If timer creation fails, just continue without it
                self._timer = None

    def stop(self):
        """Stops the session manager - GUARANTEED to complete quickly."""
        with self._lock:
            self._active = False

            if self._timer is not None:
                try:
                    self._timer.cancel()
                except Exception:
                    pass
                finally:
                    self._timer = None
