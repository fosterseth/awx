"""
Azure AD authenticator migrator.

This module handles the migration of Azure AD authenticators from AWX to Gateway.
"""

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
        # TODO: Implement Azure AD configuration retrieval
        # Azure AD settings typically include:
        # - SOCIAL_AUTH_AZUREAD_OAUTH2_KEY
        # - SOCIAL_AUTH_AZUREAD_OAUTH2_SECRET
        # - SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY
        # - SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET
        # - SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID
        # - SOCIAL_AUTH_AZUREAD_OAUTH2_ORGANIZATION_MAP
        # - SOCIAL_AUTH_AZUREAD_OAUTH2_TEAM_MAP
        found_configs = []
        return found_configs

    def create_gateway_authenticator(self, config):
        """Create an Azure AD authenticator in Gateway."""
        # TODO: Implement Azure AD authenticator creation
        # When implementing, use this pattern for slug generation:
        # client_id = settings.get('SOCIAL_AUTH_AZUREAD_OAUTH2_KEY', 'azure')
        # authenticator_slug = self._generate_authenticator_slug('azure_ad', category, client_id)
        # Azure AD requires:
        # - Application ID and secret
        # - Tenant ID (for tenant-specific auth)
        # - Proper OAuth2 endpoints for Azure
        self._write_output('Azure AD authenticator creation not yet implemented', 'warning')
        return False
