"""
GitHub authenticator migrator.

This module handles the migration of GitHub authenticators from AWX to Gateway.
"""

from django.conf import settings
from awx.conf import settings_registry
from awx.main.utils.gateway_mapping import org_map_to_gateway_format, team_map_to_gateway_format
from awx.sso.utils.base_migrator import BaseAuthenticatorMigrator
import re


class GitHubMigrator(BaseAuthenticatorMigrator):
    """
    Handles the migration of GitHub authenticators from AWX to Gateway.
    """

    def get_authenticator_type(self):
        """Get the human-readable authenticator type name."""
        return "GitHub"

    def get_controller_config(self):
        """
        Export all GitHub authenticators. A GitHub authenticator is only exported if both,
        id and secret, are defined. Otherwise it will be skipped.

        Returns:
            list: List of configured GitHub authentication providers with their settings
        """
        github_categories = ['github', 'github-org', 'github-team', 'github-enterprise', 'github-enterprise-org', 'github-enterprise-team']
        login_redirect_override = getattr(settings, "LOGIN_REDIRECT_OVERRIDE", None)

        found_configs = []

        for category in github_categories:
            try:
                category_settings = settings_registry.get_registered_settings(category_slug=category)
                if category_settings:
                    config_data = {}

                    key_setting = None
                    secret_setting = None

                    # Ensure category_settings is iterable and contains strings
                    if isinstance(category_settings, re.Pattern) or not hasattr(category_settings, '__iter__') or isinstance(category_settings, str):
                        continue

                    for setting_name in category_settings:
                        # Skip if setting_name is not a string (e.g., regex pattern)
                        if not isinstance(setting_name, str):
                            continue
                        if setting_name.endswith('_KEY'):
                            key_setting = setting_name
                        elif setting_name.endswith('_SECRET'):
                            secret_setting = setting_name

                    # Skip this category if KEY or SECRET is missing or empty
                    if not key_setting or not secret_setting:
                        continue

                    key_value = getattr(settings, key_setting, None)
                    secret_value = getattr(settings, secret_setting, None)

                    # Skip this category if OIDC Key and/or Secret are not configured
                    if not key_value or not secret_value:
                        continue

                    # If we have both key and secret, collect all settings
                    org_map_setting_name = None
                    team_map_setting_name = None

                    for setting_name in category_settings:
                        # Skip if setting_name is not a string (e.g., regex pattern)
                        if not isinstance(setting_name, str):
                            continue
                        value = getattr(settings, setting_name, None)
                        config_data[setting_name] = value

                        # Capture org and team map setting names for special processing
                        if setting_name.endswith('_ORGANIZATION_MAP'):
                            org_map_setting_name = setting_name
                        elif setting_name.endswith('_TEAM_MAP'):
                            team_map_setting_name = setting_name

                    # Get org and team mappings using the new fallback functions
                    org_map_value = self.get_social_org_map(org_map_setting_name) if org_map_setting_name else {}
                    team_map_value = self.get_social_team_map(team_map_setting_name) if team_map_setting_name else {}

                    # Convert GitHub org and team mappings from AWX to the Gateway format
                    # Start with order 1 and maintain sequence across both org and team mappers
                    org_mappers, next_order = org_map_to_gateway_format(org_map_value, start_order=1)
                    team_mappers, _ = team_map_to_gateway_format(team_map_value, start_order=next_order)

                    found_configs.append(
                        {
                            'category': category,
                            'settings': config_data,
                            'org_mappers': org_mappers,
                            'team_mappers': team_mappers,
                            'login_redirect_override': login_redirect_override,
                        }
                    )

            except Exception as e:
                raise Exception(f'Could not retrieve {category} settings: {str(e)}')

        return found_configs

    def create_gateway_authenticator(self, config):
        """Create a GitHub/OIDC authenticator in Gateway."""
        category = config['category']
        settings = config['settings']

        # Extract the OAuth2 credentials
        key_value = None
        secret_value = None

        for setting_name, value in settings.items():
            if setting_name.endswith('_KEY') and value:
                key_value = value
            elif setting_name.endswith('_SECRET') and value:
                secret_value = value

        if not key_value or not secret_value:
            self._write_output(f'Skipping {category}: missing OAuth2 credentials', 'warning')
            return False

        # Generate authenticator name and slug
        authenticator_name = category
        authenticator_slug = self._generate_authenticator_slug('github', category)

        # Map AWX category to Gateway authenticator type
        type_mapping = {
            'github': 'ansible_base.authentication.authenticator_plugins.github',
            'github-org': 'ansible_base.authentication.authenticator_plugins.github_org',
            'github-team': 'ansible_base.authentication.authenticator_plugins.github_team',
            'github-enterprise': 'ansible_base.authentication.authenticator_plugins.github_enterprise',
            'github-enterprise-org': 'ansible_base.authentication.authenticator_plugins.github_enterprise_org',
            'github-enterprise-team': 'ansible_base.authentication.authenticator_plugins.github_enterprise_team',
        }

        authenticator_type = type_mapping.get(category)
        if not authenticator_type:
            self._write_output(f'Unknown category {category}, skipping', 'warning')
            return False

        self._write_output(f'\n--- Processing {category} authenticator ---')
        self._write_output(f'Name: {authenticator_name}')
        self._write_output(f'Slug: {authenticator_slug}')
        self._write_output(f'Type: {authenticator_type}')
        self._write_output(f'Client ID: {key_value}')
        self._write_output(f'Client Secret: {"*" * 8}')

        # Build Gateway authenticator configuration
        gateway_config = {
            "name": authenticator_name,
            "slug": authenticator_slug,
            "type": authenticator_type,
            "enabled": True,
            "create_objects": True,  # Allow Gateway to create users/orgs/teams
            "remove_users": False,  # Don't remove users by default
            "configuration": {"KEY": key_value, "SECRET": secret_value},
        }

        # Add any additional configuration based on AWX settings
        additional_config = self._build_additional_config(category, settings)
        gateway_config["configuration"].update(additional_config)

        # GitHub authenticators have auto-generated fields that should be ignored during comparison
        # CALLBACK_URL - automatically created by Gateway
        # SCOPE - relevant for mappers with team/org requirement, allows to read the org or team
        # SECRET - the secret is encrypted in Gateway, we have no way of comparing the decrypted value
        ignore_keys = ['CALLBACK_URL', 'SCOPE']

        # Submit the authenticator (create or update as needed)
        result = self.submit_authenticator(gateway_config, ignore_keys, config)

        # Handle LOGIN_REDIRECT_OVERRIDE if applicable
        valid_login_urls = [f'/sso/login/{category}', f'/sso/login/{category}/']
        self.handle_login_override(config, valid_login_urls)

        return result

    def _build_additional_config(self, category, settings):
        """Build additional configuration for specific authenticator types."""
        additional_config = {}

        # Add scope configuration if present
        for setting_name, value in settings.items():
            if setting_name.endswith('_SCOPE') and value:
                additional_config['SCOPE'] = value
                break

        # Add GitHub Enterprise URL if present
        if 'enterprise' in category:
            for setting_name, value in settings.items():
                if setting_name.endswith('_API_URL') and value:
                    additional_config['API_URL'] = value
                elif setting_name.endswith('_URL') and value:
                    additional_config['URL'] = value

        # Add organization name for org-specific authenticators
        if 'org' in category:
            for setting_name, value in settings.items():
                if setting_name.endswith('_NAME') and value:
                    additional_config['NAME'] = value
                    break

        # Add team ID for team-specific authenticators
        if 'team' in category:
            for setting_name, value in settings.items():
                if setting_name.endswith('_ID') and value:
                    additional_config['ID'] = value
                    break

        return additional_config
