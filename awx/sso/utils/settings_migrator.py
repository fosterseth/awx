"""
Settings migrator.

This module handles the migration of AWX settings to Gateway.
"""

from django.conf import settings
from awx.sso.utils.base_migrator import BaseAuthenticatorMigrator


class SettingsMigrator(BaseAuthenticatorMigrator):
    """
    Handles the migration of AWX settings to Gateway.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Define transformer functions for each setting
        self.setting_transformers = {
            'SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL': self._transform_social_auth_username_is_full_email,
            'ALLOW_OAUTH2_FOR_EXTERNAL_USERS': self._transform_allow_oauth2_for_external_users,
        }

    def _convert_setting_name(self, setting):
        keys = {
            "CUSTOM_LOGIN_INFO": "custom_login_info",
            "CUSTOM_LOGO": "custom_logo",
        }
        return keys.get(setting, setting)

    def _transform_social_auth_username_is_full_email(self, value):
        # SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL is a boolean and does not need to be transformed
        return value

    def _transform_allow_oauth2_for_external_users(self, value):
        # ALLOW_OAUTH2_FOR_EXTERNAL_USERS is a boolean and does not need to be transformed
        return value

    def get_authenticator_type(self):
        """Get the human-readable authenticator type name."""
        return "Settings"

    def get_controller_config(self):
        """
        Export relevant AWX settings that need to be migrated to Gateway.

        Returns:
            list: List of configured settings that need to be migrated
        """
        # Define settings that should be migrated from AWX to Gateway
        settings_to_migrate = ['SESSION_COOKIE_AGE', 'SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL', 'ALLOW_OAUTH2_FOR_EXTERNAL_USERS']

        # Add LOGIN_REDIRECT_OVERRIDE to the list if no authenticator migrator has handled it
        if not BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator:
            settings_to_migrate.append("LOGIN_REDIRECT_OVERRIDE")

        found_configs = []

        for setting_name in settings_to_migrate:
            setting_value = getattr(settings, setting_name, None)

            # Only include settings that have non-None and non-empty values
            if setting_value is not None and setting_value != "":
                # Apply transformer function if available
                transformer = self.setting_transformers.get(setting_name)
                if transformer:
                    setting_value = transformer(setting_value)

                # Skip migration if transformer returned None or empty string
                if setting_value is not None and setting_value != "":
                    found_configs.append(
                        {
                            'category': 'global-settings',
                            'setting_name': setting_name,
                            'setting_value': setting_value,
                            'org_mappers': [],  # Settings don't have mappers
                            'team_mappers': [],  # Settings don't have mappers
                            'role_mappers': [],  # Settings don't have mappers
                            'allow_mappers': [],  # Settings don't have mappers
                        }
                    )
                else:
                    self._write_output(f'\nIgnoring {setting_name} because it is None or empty after transformation')
            else:
                self._write_output(f'\nIgnoring {setting_name} because it is None or empty')

        return found_configs

    def create_gateway_authenticator(self, config):
        """
        Migrate AWX settings to Gateway.

        Note: This doesn't create authenticators, but updates Gateway settings.
        """
        setting_name = config['setting_name']
        setting_value = config['setting_value']

        self._write_output(f'\n--- Migrating setting: {setting_name} ---')
        self._write_output(f'New value: {setting_value}')

        try:
            gateway_setting_name = self._convert_setting_name(setting_name)

            # Use the new update_gateway_setting method
            self.gateway_client.update_gateway_setting(gateway_setting_name, setting_value)

            self._write_output(f'✓ Successfully migrated setting: {setting_name}', 'success')

            # Return success result in the expected format
            return {'success': True, 'action': 'updated', 'error': None}

        except Exception as e:
            self._write_output(f'✗ Failed to migrate setting {setting_name}: {str(e)}', 'error')
            return {'success': False, 'action': 'failed', 'error': str(e)}

    def migrate(self):
        """
        Main entry point - orchestrates the settings migration process.

        Returns:
            dict: Summary of migration results
        """
        # Get settings from AWX/Controller
        configs = self.get_controller_config()

        if not configs:
            self._write_output('No settings found to migrate.', 'warning')
            return {
                'created': 0,
                'updated': 0,
                'unchanged': 0,
                'failed': 0,
                'mappers_created': 0,
                'mappers_updated': 0,
                'mappers_failed': 0,
                'settings_created': 0,
                'settings_updated': 0,
                'settings_unchanged': 0,
                'settings_failed': 0,
            }

        self._write_output(f'Found {len(configs)} setting(s) to migrate.', 'success')

        # Process each setting
        created_settings = []
        updated_settings = []
        unchanged_settings = []
        failed_settings = []

        for config in configs:
            result = self.create_gateway_authenticator(config)
            if result['success']:
                if result['action'] == 'created':
                    created_settings.append(config)
                elif result['action'] == 'updated':
                    updated_settings.append(config)
                elif result['action'] == 'skipped':
                    unchanged_settings.append(config)
            else:
                failed_settings.append(config)

        # Settings don't have mappers, or authenticators, so authenticator and mapper counts are always 0
        return {
            'created': 0,
            'updated': 0,
            'unchanged': 0,
            'failed': 0,
            'mappers_created': 0,
            'mappers_updated': 0,
            'mappers_failed': 0,
            'settings_created': len(created_settings),
            'settings_updated': len(updated_settings),
            'settings_unchanged': len(unchanged_settings),
            'settings_failed': len(failed_settings),
        }
