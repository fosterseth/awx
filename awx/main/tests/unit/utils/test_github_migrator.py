"""
Unit tests for GitHub authenticator migrator functionality.
"""

from unittest.mock import Mock, patch
from awx.sso.utils.github_migrator import GitHubMigrator


class TestGitHubMigrator:
    """Tests for GitHubMigrator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.gateway_client = Mock()
        self.command = Mock()
        self.migrator = GitHubMigrator(self.gateway_client, self.command)

    def test_create_gateway_authenticator_returns_boolean_causes_crash(self):
        """
        Test that verifies create_gateway_authenticator returns proper dictionary
        structure instead of boolean when credentials are missing.

        This test verifies the fix for the bug.
        """
        # Mock the get_controller_config to return a GitHub config with missing credentials
        github_config_missing_creds = {
            'category': 'github',
            'settings': {'SOCIAL_AUTH_GITHUB_KEY': '', 'SOCIAL_AUTH_GITHUB_SECRET': 'test-secret'},  # Missing key
            'org_mappers': [],
            'team_mappers': [],
            'login_redirect_override': None,
        }

        with patch.object(self.migrator, 'get_controller_config', return_value=[github_config_missing_creds]):
            with patch.object(self.migrator, '_write_output'):  # Mock output to avoid noise
                # This should NOT crash now that the bug is fixed
                result = self.migrator.migrate()

                # Verify the migration ran successfully without crashing
                assert 'created' in result
                assert 'failed' in result
                # Should have failed=1 since the config has success=False (missing credentials)
                assert result['failed'] == 1

    def test_create_gateway_authenticator_returns_boolean_with_unknown_category(self):
        """
        Test that verifies create_gateway_authenticator returns proper dictionary
        structure instead of boolean when category is unknown.

        This test verifies the fix for the bug.
        """
        # Mock the get_controller_config to return a GitHub config with unknown category
        github_config_unknown_category = {
            'category': 'unknown-category',
            'settings': {'SOCIAL_AUTH_UNKNOWN_KEY': 'test-key', 'SOCIAL_AUTH_UNKNOWN_SECRET': 'test-secret'},
            'org_mappers': [],
            'team_mappers': [],
            'login_redirect_override': None,
        }

        with patch.object(self.migrator, 'get_controller_config', return_value=[github_config_unknown_category]):
            with patch.object(self.migrator, '_write_output'):  # Mock output to avoid noise
                # This should NOT crash now that the bug is fixed
                result = self.migrator.migrate()

                # Verify the migration ran successfully without crashing
                assert 'created' in result
                assert 'failed' in result
                # Should have failed=1 since the config has success=False (unknown category)
                assert result['failed'] == 1

    def test_create_gateway_authenticator_direct_boolean_return_missing_creds(self):
        """
        Test that directly calls create_gateway_authenticator and verifies it returns
        proper dictionary structure instead of boolean for missing credentials.
        """
        # Config with missing key (empty string)
        config_missing_key = {
            'category': 'github',
            'settings': {'SOCIAL_AUTH_GITHUB_KEY': '', 'SOCIAL_AUTH_GITHUB_SECRET': 'test-secret'},  # Missing key
            'org_mappers': [],
            'team_mappers': [],
            'login_redirect_override': None,
        }

        with patch.object(self.migrator, '_write_output'):  # Mock output to avoid noise
            result = self.migrator.create_gateway_authenticator(config_missing_key)

            # Now the method should return a proper dictionary structure
            assert isinstance(result, dict), f"Expected dict, got {type(result)} with value: {result}"
            assert 'success' in result, f"Expected 'success' key in result: {result}"
            assert 'action' in result, f"Expected 'action' key in result: {result}"
            assert 'error' in result, f"Expected 'error' key in result: {result}"
            # Verify the expected values
            assert result['success'] is False
            assert result['action'] == 'skipped'
            assert 'Missing OAuth2 credentials' in result['error']

    def test_create_gateway_authenticator_direct_boolean_return_unknown_category(self):
        """
        Test that directly calls create_gateway_authenticator and verifies it returns
        proper dictionary structure instead of boolean for unknown category.
        """
        # Config with unknown category
        config_unknown_category = {
            'category': 'unknown-category',
            'settings': {'SOCIAL_AUTH_UNKNOWN_KEY': 'test-key', 'SOCIAL_AUTH_UNKNOWN_SECRET': 'test-secret'},
            'org_mappers': [],
            'team_mappers': [],
            'login_redirect_override': None,
        }

        with patch.object(self.migrator, '_write_output'):  # Mock output to avoid noise
            result = self.migrator.create_gateway_authenticator(config_unknown_category)

            # Now the method should return a proper dictionary structure
            assert isinstance(result, dict), f"Expected dict, got {type(result)} with value: {result}"
            assert 'success' in result, f"Expected 'success' key in result: {result}"
            assert 'action' in result, f"Expected 'action' key in result: {result}"
            assert 'error' in result, f"Expected 'error' key in result: {result}"
            # Verify the expected values
            assert result['success'] is False
            assert result['action'] == 'skipped'
            assert 'Unknown category unknown-category' in result['error']
