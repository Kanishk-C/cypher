"""Base class for command handlers to eliminate duplication."""

from abc import ABC, abstractmethod
from core.core import App
from interface import views
from exceptions import CoreException

class BaseCommandHandler(ABC):
    """Abstract base class for command handlers."""
    
    def __init__(self, app: App):
        self.app = app
    
    def execute(self, args):
        """Template method for command execution."""
        try:
            self._validate_profile_loaded()
            self._pre_execute(args)
            result = self._execute_impl(args)
            self._post_execute(result)
            return result
        except CoreException as e:
            views.show_error(str(e))
        except KeyboardInterrupt:
            views.show_warning(f"{self.__class__.__name__} cancelled")
        except Exception as e:
            views.show_error(f"Unexpected error: {e}")
    
    def _validate_profile_loaded(self):
        """Check if profile is loaded."""
        if not self.app.is_profile_loaded():
            raise CoreException("No profile loaded")
    
    def _pre_execute(self, args):
        """Hook for pre-execution logic."""
        pass
    
    @abstractmethod
    def _execute_impl(self, args):
        """Actual command implementation."""
        pass
    
    def _post_execute(self, result):
        """Hook for post-execution logic."""
        pass
