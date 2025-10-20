import pytest
from unittest.mock import Mock, patch
from src.ui import commands
from src.exceptions import DuplicateEntryError


class TestCommandHandlers:
    """Test UI command handlers."""

    @pytest.fixture
    def mock_app(self):
        """Mock App instance."""
        app = Mock()
        app.is_profile_loaded.return_value = True
        return app

    def test_add_command_validation(self, mock_app):
        """Add command should validate inputs."""
        args = Mock(service="", username="test")

        with patch("src.ui.views.prompt_input", return_value=""):
            with patch("src.ui.views.show_warning") as mock_warning:
                commands.add_command(args, mock_app)
                mock_warning.assert_called()

    def test_add_command_duplicate_entry(self, mock_app):
        """Add command should handle duplicate entries."""
        args = Mock(service="github", username="user")
        mock_app.add_password.side_effect = DuplicateEntryError("Duplicate")

        with patch("src.ui.views.prompt_input", return_value="test"):
            with patch("src.ui.views.prompt_password_masked", return_value="Pass123"):
                with patch("src.ui.views.show_error") as mock_error:
                    commands.add_command(args, mock_app)
                    mock_error.assert_called()

    def test_get_command_single_account(self, mock_app):
        """Get command with single account should display directly."""
        args = Mock(service="github", username=None)
        mock_app.get_entries_by_service.return_value = [
            {"username": "user1", "password": "pass1", "notes": ""}
        ]

        with patch("src.ui.views.display_entry_details") as mock_display:
            commands.get_command(args, mock_app)
            mock_display.assert_called_once()

    def test_search_command_with_results(self, mock_app):
        """Search should display matching entries."""
        args = Mock(query="git")
        mock_app.list_all_entries.return_value = [
            ("github", "user1"),
            ("gitlab", "user2"),
            ("twitter", "user3"),
        ]

        with patch("src.ui.views.display_entry_list") as mock_display:
            commands.search_command(args, mock_app)
            # Should display only github and gitlab
            call_args = mock_display.call_args[0][0]
            assert len(call_args) == 2

    def test_generate_password_command(self, mock_app):
        """Password generation should use secure random."""
        args = Mock()

        with patch("src.ui.views.prompt_input", return_value="16"):
            with patch(
                "src.ui.views.confirm_action",
                side_effect=[True, True, True, False, False],
            ):
                with patch("src.ui.views.display_generated_password"):
                    with patch("secrets.choice") as mock_choice:
                        mock_choice.side_effect = list("abcABC123")
                        commands.generate_password_command(args, mock_app)
                        # Should use secrets.choice (after fix)
