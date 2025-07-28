"""
Google OAuth2 authenticator migrator.

This module handles the migration of Google OAuth2 authenticators from AWX to Gateway.
"""

from awx.main.utils.gateway_mapping import org_map_to_gateway_format, team_map_to_gateway_format
from awx.sso.utils.base_migrator import BaseAuthenticatorMigrator


class GoogleOAuth2Migrator(BaseAuthenticatorMigrator):
    """
    Handles the migration of Google OAuth2 authenticators from AWX to Gateway.
    """

    def get_authenticator_type(self):
        """Get the human-readable authenticator type name."""
        return "Google OAuth2"

    def get_controller_config(self):
        """
        Export Google OAuth2 authenticators. A Google OAuth2 authenticator is only exported if
        KEY and SECRET are configured.

        Returns:
            list: List of configured Google OAuth2 authentication providers with their settings
        """
        from django.conf import settings

        if not getattr(settings, 'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY', None):
            return []

        config_data = {
            'SOCIAL_AUTH_GOOGLE_OAUTH2_CALLBACK_URL': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_CALLBACK_URL,
            'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            'SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            'SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE,
        }

        login_redirect_override = getattr(settings, "LOGIN_REDIRECT_OVERRIDE", None)

        return [
            {
                "category": self.get_authenticator_type(),
                "settings": config_data,
                "login_redirect_override": login_redirect_override,
            }
        ]

    def _build_mappers(self):
        org_map = self.get_social_org_map('SOCIAL_AUTH_GOOGLE_OAUTH2_ORGANIZATION_MAP')
        team_map = self.get_social_team_map('SOCIAL_AUTH_GOOGLE_OAUTH2_TEAM_MAP')

        mappers, order = org_map_to_gateway_format(org_map, 1)
        team_mappers, _ = team_map_to_gateway_format(team_map, order)

        mappers.extend(team_mappers)

        return mappers

    def create_gateway_authenticator(self, config):
        """Create a Google OAuth2 authenticator in Gateway."""
        category = config["category"]
        config_settings = config['settings']

        authenticator_slug = self._generate_authenticator_slug('google-oauth2', category.replace(" ", "-"))

        self._write_output(f"\n--- Processing {category} authenticator ---")

        gateway_config = {
            "name": "google",
            "slug": authenticator_slug,
            "type": "ansible_base.authentication.authenticator_plugins.google_oauth2",
            "enabled": True,
            "create_objects": True,  # Allow Gateway to create users/orgs/teams
            "remove_users": False,  # Don't remove users by default
            "configuration": {
                "KEY": config_settings.get('SOCIAL_AUTH_GOOGLE_OAUTH2_KEY'),
                "SECRET": config_settings.get('SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET'),
                "REDIRECT_STATE": True,
            },
            "mappers": self._build_mappers(),
        }

        ignore_keys = ["ACCESS_TOKEN_METHOD", "REVOKE_TOKEN_METHOD"]
        optional = {
            "CALLBACK_URL": config_settings.get('SOCIAL_AUTH_GOOGLE_OAUTH2_CALLBACK_URL'),
            "SCOPE": config_settings.get('SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE'),
        }
        for key, value in optional.items():
            if value:
                gateway_config["configuration"][key] = value
            else:
                ignore_keys.append(key)

        result = self.submit_authenticator(gateway_config, ignore_keys, config)

        # Handle LOGIN_REDIRECT_OVERRIDE if applicable
        valid_login_urls = ['/sso/login/google-oauth2']
        self.handle_login_override(config, valid_login_urls)

        return result
