"""
Unit tests for SettingsMigrator class.
"""

import pytest
from unittest.mock import Mock, patch
from awx.sso.utils.settings_migrator import SettingsMigrator


class TestSettingsMigrator:
    """Tests for SettingsMigrator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.gateway_client = Mock()
        self.command = Mock()
        self.migrator = SettingsMigrator(self.gateway_client, self.command)

    def test_get_authenticator_type(self):
        """Test that get_authenticator_type returns 'Settings'."""
        assert self.migrator.get_authenticator_type() == "Settings"

    @pytest.mark.parametrize(
        "input_name,expected_output",
        [
            ('CUSTOM_LOGIN_INFO', 'custom_login_info'),
            ('CUSTOM_LOGO', 'custom_logo'),
            ('UNKNOWN_SETTING', 'UNKNOWN_SETTING'),
            ('ANOTHER_UNKNOWN', 'ANOTHER_UNKNOWN'),
        ],
    )
    def test_convert_setting_name(self, input_name, expected_output):
        """Test setting name conversion."""
        result = self.migrator._convert_setting_name(input_name)
        assert result == expected_output

    @pytest.mark.parametrize(
        "transformer_method,test_values",
        [
            ('_transform_social_auth_username_is_full_email', [True, False]),
            ('_transform_allow_oauth2_for_external_users', [True, False]),
        ],
    )
    def test_boolean_transformers(self, transformer_method, test_values):
        """Test that boolean transformers return values as-is."""
        transformer = getattr(self.migrator, transformer_method)
        for value in test_values:
            assert transformer(value) is value

    @pytest.mark.parametrize(
        "settings_values,expected_count",
        [
            # Test case: all settings are None
            (
                {
                    'SESSION_COOKIE_AGE': None,
                    'SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL': None,
                    'ALLOW_OAUTH2_FOR_EXTERNAL_USERS': None,
                    'LOGIN_REDIRECT_OVERRIDE': None,
                    'ORG_ADMINS_CAN_SEE_ALL_USERS': None,
                    'MANAGE_ORGANIZATION_AUTH': None,
                },
                0,
            ),
            # Test case: all settings are empty strings
            (
                {
                    'SESSION_COOKIE_AGE': "",
                    'SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL': "",
                    'ALLOW_OAUTH2_FOR_EXTERNAL_USERS': "",
                    'LOGIN_REDIRECT_OVERRIDE': "",
                    'ORG_ADMINS_CAN_SEE_ALL_USERS': "",
                    'MANAGE_ORGANIZATION_AUTH': "",
                },
                0,
            ),
            # Test case: only new settings have values
            (
                {
                    'SESSION_COOKIE_AGE': None,
                    'SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL': None,
                    'ALLOW_OAUTH2_FOR_EXTERNAL_USERS': None,
                    'LOGIN_REDIRECT_OVERRIDE': None,
                    'ORG_ADMINS_CAN_SEE_ALL_USERS': True,
                    'MANAGE_ORGANIZATION_AUTH': False,
                },
                2,
            ),
        ],
    )
    @patch('awx.sso.utils.settings_migrator.settings')
    def test_get_controller_config_various_scenarios(self, mock_settings, settings_values, expected_count):
        """Test get_controller_config with various setting combinations."""
        # Apply the settings values to the mock
        for setting_name, setting_value in settings_values.items():
            setattr(mock_settings, setting_name, setting_value)

        result = self.migrator.get_controller_config()
        assert len(result) == expected_count

        # Verify structure if we have results
        if result:
            for config in result:
                assert config['category'] == 'global-settings'
                assert 'setting_name' in config
                assert 'setting_value' in config
                assert config['org_mappers'] == []
                assert config['team_mappers'] == []
                assert config['role_mappers'] == []
                assert config['allow_mappers'] == []

    @patch('awx.sso.utils.settings_migrator.settings')
    def test_get_controller_config_with_all_settings(self, mock_settings):
        """Test get_controller_config with all settings configured."""
        # Mock all settings with valid values
        mock_settings.SESSION_COOKIE_AGE = 3600
        mock_settings.SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = True
        mock_settings.ALLOW_OAUTH2_FOR_EXTERNAL_USERS = False
        mock_settings.LOGIN_REDIRECT_OVERRIDE = "https://example.com/login"
        mock_settings.ORG_ADMINS_CAN_SEE_ALL_USERS = True
        mock_settings.MANAGE_ORGANIZATION_AUTH = False

        # Mock the login redirect override to not be set by migrator
        with patch.object(self.migrator.__class__.__bases__[0], 'login_redirect_override_set_by_migrator', False):
            result = self.migrator.get_controller_config()

        assert len(result) == 6

        # Check that all expected settings are present
        setting_names = [config['setting_name'] for config in result]
        expected_settings = [
            'SESSION_COOKIE_AGE',
            'SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL',
            'ALLOW_OAUTH2_FOR_EXTERNAL_USERS',
            'LOGIN_REDIRECT_OVERRIDE',
            'ORG_ADMINS_CAN_SEE_ALL_USERS',
            'MANAGE_ORGANIZATION_AUTH',
        ]

        for setting in expected_settings:
            assert setting in setting_names

        # Verify structure of returned configs
        for config in result:
            assert config['category'] == 'global-settings'
            assert 'setting_name' in config
            assert 'setting_value' in config
            assert config['org_mappers'] == []
            assert config['team_mappers'] == []
            assert config['role_mappers'] == []
            assert config['allow_mappers'] == []

    @patch('awx.sso.utils.settings_migrator.settings')
    def test_get_controller_config_with_new_settings_only(self, mock_settings):
        """Test get_controller_config with only the new settings configured."""
        # Mock only the new settings
        mock_settings.SESSION_COOKIE_AGE = None
        mock_settings.SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = None
        mock_settings.ALLOW_OAUTH2_FOR_EXTERNAL_USERS = None
        mock_settings.LOGIN_REDIRECT_OVERRIDE = None
        mock_settings.ORG_ADMINS_CAN_SEE_ALL_USERS = True
        mock_settings.MANAGE_ORGANIZATION_AUTH = False

        result = self.migrator.get_controller_config()

        assert len(result) == 2

        # Check the new settings are present
        setting_names = [config['setting_name'] for config in result]
        assert 'ORG_ADMINS_CAN_SEE_ALL_USERS' in setting_names
        assert 'MANAGE_ORGANIZATION_AUTH' in setting_names

        # Verify the values
        org_admins_config = next(c for c in result if c['setting_name'] == 'ORG_ADMINS_CAN_SEE_ALL_USERS')
        assert org_admins_config['setting_value'] is True

        manage_org_auth_config = next(c for c in result if c['setting_name'] == 'MANAGE_ORGANIZATION_AUTH')
        assert manage_org_auth_config['setting_value'] is False

    @patch('awx.sso.utils.settings_migrator.settings')
    def test_get_controller_config_with_login_redirect_override_from_migrator(self, mock_settings):
        """Test get_controller_config when LOGIN_REDIRECT_OVERRIDE is set by migrator."""
        # Mock settings
        mock_settings.SESSION_COOKIE_AGE = None
        mock_settings.SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = None
        mock_settings.ALLOW_OAUTH2_FOR_EXTERNAL_USERS = None
        mock_settings.LOGIN_REDIRECT_OVERRIDE = "https://original.com/login"
        mock_settings.ORG_ADMINS_CAN_SEE_ALL_USERS = None
        mock_settings.MANAGE_ORGANIZATION_AUTH = None

        # Mock the login redirect override to be set by migrator
        with patch.object(self.migrator.__class__.__bases__[0], 'login_redirect_override_set_by_migrator', True):
            with patch.object(self.migrator.__class__.__bases__[0], 'login_redirect_override_new_url', 'https://new.com/login'):
                result = self.migrator.get_controller_config()

        assert len(result) == 1
        assert result[0]['setting_name'] == 'LOGIN_REDIRECT_OVERRIDE'
        assert result[0]['setting_value'] == 'https://new.com/login'  # Should use the migrator URL

    @pytest.mark.parametrize(
        "config,current_value,expected_action,should_update",
        [
            # Test case: setting needs update
            ({'setting_name': 'ORG_ADMINS_CAN_SEE_ALL_USERS', 'setting_value': True}, False, 'updated', True),
            # Test case: setting is unchanged
            ({'setting_name': 'MANAGE_ORGANIZATION_AUTH', 'setting_value': False}, False, 'skipped', False),
            # Test case: another setting needs update
            ({'setting_name': 'SESSION_COOKIE_AGE', 'setting_value': 7200}, 3600, 'updated', True),
            # Test case: another setting is unchanged
            ({'setting_name': 'SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL', 'setting_value': True}, True, 'skipped', False),
        ],
    )
    def test_create_gateway_authenticator_success_scenarios(self, config, current_value, expected_action, should_update):
        """Test create_gateway_authenticator success scenarios."""
        # Mock gateway client methods
        self.gateway_client.get_gateway_setting.return_value = current_value
        self.gateway_client.update_gateway_setting.return_value = None

        result = self.migrator.create_gateway_authenticator(config)

        assert result['success'] is True
        assert result['action'] == expected_action
        assert result['error'] is None

        # Verify gateway client calls
        expected_setting_name = config['setting_name']
        self.gateway_client.get_gateway_setting.assert_called_once_with(expected_setting_name)

        if should_update:
            self.gateway_client.update_gateway_setting.assert_called_once_with(expected_setting_name, config['setting_value'])
        else:
            self.gateway_client.update_gateway_setting.assert_not_called()

        # Reset mocks for next iteration
        self.gateway_client.reset_mock()

    def test_create_gateway_authenticator_with_setting_name_conversion(self):
        """Test create_gateway_authenticator with setting name that needs conversion."""
        config = {'setting_name': 'CUSTOM_LOGIN_INFO', 'setting_value': 'Some custom info'}

        # Mock gateway client methods
        self.gateway_client.get_gateway_setting.return_value = 'Old info'  # Different value
        self.gateway_client.update_gateway_setting.return_value = None

        result = self.migrator.create_gateway_authenticator(config)

        assert result['success'] is True
        assert result['action'] == 'updated'

        # Verify gateway client was called with converted name
        self.gateway_client.get_gateway_setting.assert_called_once_with('custom_login_info')
        self.gateway_client.update_gateway_setting.assert_called_once_with('custom_login_info', 'Some custom info')

    def test_create_gateway_authenticator_failure(self):
        """Test create_gateway_authenticator when gateway update fails."""
        config = {'setting_name': 'SESSION_COOKIE_AGE', 'setting_value': 7200}

        # Mock gateway client to raise exception
        self.gateway_client.get_gateway_setting.return_value = 3600
        self.gateway_client.update_gateway_setting.side_effect = Exception("Gateway error")

        result = self.migrator.create_gateway_authenticator(config)

        assert result['success'] is False
        assert result['action'] == 'failed'
        assert result['error'] == 'Gateway error'

    @pytest.mark.parametrize(
        "scenario,settings_config,gateway_responses,update_side_effects,expected_counts",
        [
            # Scenario 1: No settings configured
            (
                "no_settings",
                {
                    'SESSION_COOKIE_AGE': None,
                    'SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL': None,
                    'ALLOW_OAUTH2_FOR_EXTERNAL_USERS': None,
                    'LOGIN_REDIRECT_OVERRIDE': None,
                    'ORG_ADMINS_CAN_SEE_ALL_USERS': None,
                    'MANAGE_ORGANIZATION_AUTH': None,
                },
                [],  # No gateway calls expected
                [],  # No update calls expected
                {'settings_created': 0, 'settings_updated': 0, 'settings_unchanged': 0, 'settings_failed': 0},
            ),
            # Scenario 2: All updates successful
            (
                "successful_updates",
                {
                    'SESSION_COOKIE_AGE': None,
                    'SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL': None,
                    'ALLOW_OAUTH2_FOR_EXTERNAL_USERS': None,
                    'LOGIN_REDIRECT_OVERRIDE': None,
                    'ORG_ADMINS_CAN_SEE_ALL_USERS': True,
                    'MANAGE_ORGANIZATION_AUTH': False,
                },
                [False, True],  # Different values to trigger updates
                [None, None],  # Successful updates
                {'settings_created': 0, 'settings_updated': 2, 'settings_unchanged': 0, 'settings_failed': 0},
            ),
            # Scenario 3: One unchanged, one updated
            (
                "mixed_results",
                {
                    'SESSION_COOKIE_AGE': None,
                    'SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL': None,
                    'ALLOW_OAUTH2_FOR_EXTERNAL_USERS': None,
                    'LOGIN_REDIRECT_OVERRIDE': None,
                    'ORG_ADMINS_CAN_SEE_ALL_USERS': True,
                    'MANAGE_ORGANIZATION_AUTH': False,
                },
                [True, True],  # Gateway returns: ORG_ADMINS_CAN_SEE_ALL_USERS=True (unchanged), MANAGE_ORGANIZATION_AUTH=True (needs update)
                [ValueError("Update failed")],  # Only one update call (for MANAGE_ORGANIZATION_AUTH), and it fails
                {'settings_created': 0, 'settings_updated': 0, 'settings_unchanged': 1, 'settings_failed': 1},
            ),
        ],
    )
    @patch('awx.sso.utils.settings_migrator.settings')
    def test_migrate_scenarios(self, mock_settings, scenario, settings_config, gateway_responses, update_side_effects, expected_counts):
        """Test migrate method with various scenarios."""
        # Apply settings configuration
        for setting_name, setting_value in settings_config.items():
            setattr(mock_settings, setting_name, setting_value)

        # Mock gateway client responses
        if gateway_responses:
            self.gateway_client.get_gateway_setting.side_effect = gateway_responses
        if update_side_effects:
            self.gateway_client.update_gateway_setting.side_effect = update_side_effects

        # Mock the login redirect override to not be set by migrator for these tests
        with patch.object(self.migrator.__class__.__bases__[0], 'login_redirect_override_set_by_migrator', False):
            result = self.migrator.migrate()

        # Verify expected counts
        for key, expected_value in expected_counts.items():
            assert result[key] == expected_value, f"Scenario {scenario}: Expected {key}={expected_value}, got {result[key]}"

        # All authenticator/mapper counts should be 0 since settings don't have them
        authenticator_mapper_keys = ['created', 'updated', 'unchanged', 'failed', 'mappers_created', 'mappers_updated', 'mappers_failed']
        for key in authenticator_mapper_keys:
            assert result[key] == 0, f"Scenario {scenario}: Expected {key}=0, got {result[key]}"

    def test_setting_transformers_defined(self):
        """Test that setting transformers are properly defined."""
        expected_transformers = {'SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL', 'ALLOW_OAUTH2_FOR_EXTERNAL_USERS'}

        actual_transformers = set(self.migrator.setting_transformers.keys())
        assert actual_transformers == expected_transformers

    @pytest.mark.parametrize(
        "transformer_return_value,expected_result_count",
        [
            (None, 0),  # Transformer returns None - should be excluded
            ("", 0),  # Transformer returns empty string - should be excluded
            (True, 1),  # Transformer returns valid value - should be included
        ],
    )
    @patch('awx.sso.utils.settings_migrator.settings')
    def test_get_controller_config_transformer_edge_cases(self, mock_settings, transformer_return_value, expected_result_count):
        """Test get_controller_config when transformer returns various edge case values."""
        # Mock settings - only one setting with a value that has a transformer
        mock_settings.SESSION_COOKIE_AGE = None
        mock_settings.SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = True
        mock_settings.ALLOW_OAUTH2_FOR_EXTERNAL_USERS = None
        mock_settings.LOGIN_REDIRECT_OVERRIDE = None
        mock_settings.ORG_ADMINS_CAN_SEE_ALL_USERS = None
        mock_settings.MANAGE_ORGANIZATION_AUTH = None

        # Mock transformer to return the specified value
        # We need to patch the transformer in the dictionary, not just the method
        original_transformer = self.migrator.setting_transformers.get('SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL')
        self.migrator.setting_transformers['SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL'] = lambda x: transformer_return_value

        try:
            # Mock the login redirect override to not be set by migrator
            with patch.object(self.migrator.__class__.__bases__[0], 'login_redirect_override_set_by_migrator', False):
                result = self.migrator.get_controller_config()
        finally:
            # Restore the original transformer
            if original_transformer:
                self.migrator.setting_transformers['SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL'] = original_transformer

        assert len(result) == expected_result_count
