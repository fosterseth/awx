"""
Azure AD authenticator migrator.

This module handles the migration of Azure AD authenticators from AWX to Gateway.
"""

from django.conf import settings
from awx.main.utils.gateway_mapping import org_map_to_gateway_format, team_map_to_gateway_format
from awx.sso.utils.base_migrator import BaseAuthenticatorMigrator


class AzureADMigrator(BaseAuthenticatorMigrator):
    """
    Handles the migration of Azure AD authenticators from AWX to Gateway.
    """

    def get_authenticator_type(self):
        """Get the human-readable authenticator type name."""
        return "Azure AD"

    def get_controller_config(self):
        """
        Export Azure AD authenticators. An Azure AD authenticator is only exported if
        KEY and SECRET are configured.

        Returns:
            list: List of configured Azure AD authentication providers with their settings
        """
        key_value = getattr(settings, 'SOCIAL_AUTH_AZUREAD_OAUTH2_KEY', None)
        secret_value = getattr(settings, 'SOCIAL_AUTH_AZUREAD_OAUTH2_SECRET', None)

        # Skip this category if OIDC Key and/or Secret are not configured
        if not key_value or not secret_value:
            return []

        # If we have both key and secret, collect all settings
        org_map_value = getattr(settings, 'SOCIAL_AUTH_AZUREAD_OAUTH2_ORGANIZATION_MAP', None)
        team_map_value = getattr(settings, 'SOCIAL_AUTH_AZUREAD_OAUTH2_TEAM_MAP', None)
        login_redirect_override = getattr(settings, "LOGIN_REDIRECT_OVERRIDE", None)

        # Convert GitHub org and team mappings from AWX to the Gateway format
        # Start with order 1 and maintain sequence across both org and team mappers
        org_mappers, next_order = org_map_to_gateway_format(org_map_value, start_order=1)
        team_mappers, _ = team_map_to_gateway_format(team_map_value, start_order=next_order)

        category = 'AzureAD'

        # Generate authenticator name and slug
        authenticator_name = "Controller Azure AD"
        authenticator_slug = self._generate_authenticator_slug("azure_ad", category)

        return [
            {
                'category': category,
                'settings': {
                    "name": authenticator_name,
                    "slug": authenticator_slug,
                    "type": "ansible_base.authentication.authenticator_plugins.azuread",
                    "enabled": False,
                    "create_objects": True,
                    "remove_users": False,
                    "configuration": {
                        "KEY": key_value,
                        "SECRET": secret_value,
                        "GROUPS_CLAIM": "groups",
                    },
                },
                'org_mappers': org_mappers,
                'team_mappers': team_mappers,
                'login_redirect_override': login_redirect_override,
            }
        ]

    def create_gateway_authenticator(self, config):
        """Create an Azure AD authenticator in Gateway."""

        category = config["category"]
        gateway_config = config["settings"]

        self._write_output(f"\n--- Processing {category} authenticator ---")
        self._write_output(f"Name: {gateway_config['name']}")
        self._write_output(f"Slug: {gateway_config['slug']}")
        self._write_output(f"Type: {gateway_config['type']}")

        # CALLBACK_URL - automatically created by Gateway
        # GROUPS_CLAIM - Not an AWX feature
        # ADDITIONAL_UNVERIFIED_ARGS - Not an AWX feature
        ignore_keys = ["CALLBACK_URL", "GROUPS_CLAIM"]

        # Submit the authenticator (create or update as needed)
        result = self.submit_authenticator(gateway_config, ignore_keys, config)

        # Handle LOGIN_REDIRECT_OVERRIDE if applicable
        valid_login_urls = ['/sso/login/azuread-oauth2']
        self.handle_login_override(config, valid_login_urls)

        return result
