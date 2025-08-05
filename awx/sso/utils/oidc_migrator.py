"""
Generic OIDC authenticator migrator.

This module handles the migration of generic OIDC authenticators from AWX to Gateway.
"""

from django.conf import settings
from awx.main.utils.gateway_mapping import org_map_to_gateway_format, team_map_to_gateway_format
from awx.sso.utils.base_migrator import BaseAuthenticatorMigrator


class OIDCMigrator(BaseAuthenticatorMigrator):
    """
    Handles the migration of generic OIDC authenticators from AWX to Gateway.
    """

    CATEGORY = "OIDC"
    AUTH_TYPE = "ansible_base.authentication.authenticator_plugins.oidc"

    def get_authenticator_type(self):
        """Get the human-readable authenticator type name."""
        return "OIDC"

    def get_controller_config(self):
        """
        Export generic OIDC authenticators. An OIDC authenticator is only exported if both,
        key and secret, are defined. Otherwise it will be skipped.

        Returns:
            list: List of configured OIDC authentication providers with their settings
        """
        key_value = getattr(settings, "SOCIAL_AUTH_OIDC_KEY", None)
        secret_value = getattr(settings, "SOCIAL_AUTH_OIDC_SECRET", None)
        oidc_endpoint = getattr(settings, "SOCIAL_AUTH_OIDC_OIDC_ENDPOINT", None)

        # Skip if required settings are not configured
        if not key_value or not secret_value or not oidc_endpoint:
            return []

        # Get additional OIDC configuration
        verify_ssl = getattr(settings, "SOCIAL_AUTH_OIDC_VERIFY_SSL", True)

        # Get organization and team mappings
        org_map_value = self.get_social_org_map()
        team_map_value = self.get_social_team_map()

        # Convert org and team mappings from AWX to the Gateway format
        # Start with order 1 and maintain sequence across both org and team mappers
        org_mappers, next_order = org_map_to_gateway_format(org_map_value, start_order=1)
        team_mappers, _ = team_map_to_gateway_format(team_map_value, start_order=next_order)

        config_data = {
            "name": "default",
            "type": self.AUTH_TYPE,
            "enabled": True,
            "create_objects": True,
            "remove_users": False,
            "configuration": {
                "OIDC_ENDPOINT": oidc_endpoint,
                "KEY": key_value,
                "SECRET": secret_value,
                "VERIFY_SSL": verify_ssl,
            },
        }

        return [
            {
                "category": self.CATEGORY,
                "settings": config_data,
                "org_mappers": org_mappers,
                "team_mappers": team_mappers,
            }
        ]

    def create_gateway_authenticator(self, config):
        """Create a generic OIDC authenticator in Gateway."""
        category = config["category"]
        config_settings = config["settings"]

        # Generate authenticator name and slug
        authenticator_name = "oidc"
        authenticator_slug = self._generate_authenticator_slug("oidc", category)

        self._write_output(f"\n--- Processing {category} authenticator ---")
        self._write_output(f"Name: {authenticator_name}")
        self._write_output(f"Slug: {authenticator_slug}")
        self._write_output(f"Type: {config_settings['type']}")

        # Build Gateway authenticator configuration
        gateway_config = {
            "name": authenticator_name,
            "slug": authenticator_slug,
            "type": config_settings["type"],
            "enabled": config_settings["enabled"],
            "create_objects": config_settings["create_objects"],
            "remove_users": config_settings["remove_users"],
            "configuration": config_settings["configuration"],
        }

        # OIDC authenticators have auto-generated fields that should be ignored during comparison
        # CALLBACK_URL - automatically created by Gateway
        # SCOPE - defaults are set by Gateway plugin
        # SECRET - the secret is encrypted in Gateway, we have no way of comparing the decrypted value
        ignore_keys = ['CALLBACK_URL', 'SCOPE']

        # Submit the authenticator (create or update as needed)
        result = self.submit_authenticator(gateway_config, ignore_keys, config)

        # Handle LOGIN_REDIRECT_OVERRIDE if applicable
        valid_login_urls = ['/sso/login/oidc']
        self.handle_login_override(config, valid_login_urls)

        return result
