from django.conf import settings
from awx.conf import settings_registry
from awx.main.utils.gateway_mapping import org_map_to_gateway_format, team_map_to_gateway_format


class AuthConfigMigrator:
    """
    Handles the migration of authenticators from AWX to Gateway
    TODO: this is a work in progress
    """

    """
    Export all GitHub OIDC authenticators. An OIDC authenticator is only exported if both,
    id and secret, are defined. Otherwise it will be skipped.
    Returns:
        list: List of configured GitHub authentication providers with their settings
    """

    def get_github_oidc_config(self):
        github_categories = ['github', 'github-org', 'github-team', 'github-enterprise', 'github-enterprise-org', 'github-enterprise-team', 'oidc']

        found_configs = []

        for category in github_categories:
            try:
                category_settings = settings_registry.get_registered_settings(category_slug=category)
                if category_settings:
                    config_data = {}

                    key_setting = None
                    secret_setting = None

                    # Ensure category_settings is iterable and contains strings
                    import re

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
                    org_map_value = None
                    team_map_value = None

                    for setting_name in category_settings:
                        # Skip if setting_name is not a string (e.g., regex pattern)
                        if not isinstance(setting_name, str):
                            continue
                        value = getattr(settings, setting_name, None)
                        config_data[setting_name] = value

                        # Capture org and team map values for special processing
                        if setting_name.endswith('_ORGANIZATION_MAP'):
                            org_map_value = value
                        elif setting_name.endswith('_TEAM_MAP'):
                            team_map_value = value

                    # Convert GitHub org and team mappings from AWX to the Gateway format
                    # Start with order 1 and maintain sequence across both org and team mappers
                    org_mappers, next_order = org_map_to_gateway_format(org_map_value, start_order=1)
                    team_mappers, _ = team_map_to_gateway_format(team_map_value, start_order=next_order)

                    found_configs.append({'category': category, 'settings': config_data, 'org_mappers': org_mappers, 'team_mappers': team_mappers})

            except Exception as e:
                raise Exception(f'Could not retrieve {category} settings: {str(e)}')

        return found_configs

    def get_ldap_config(self):
        """
        Export all LDAP authenticators. An LDAP authenticator is only exported if
        SERVER_URI is configured. Otherwise it will be skipped.

        Returns:
            list: List of configured LDAP authentication providers with their settings
        """
        found_configs = []

        # AWX supports up to 6 LDAP configurations: AUTH_LDAP (default) and AUTH_LDAP_1 through AUTH_LDAP_5
        ldap_instances = [''] + [f'_{i}' for i in range(1, 6)]  # ['', '_1', '_2', '_3', '_4', '_5']

        for instance in ldap_instances:
            try:
                # Build the setting prefix (AUTH_LDAP or AUTH_LDAP_1, etc.)
                prefix = f'AUTH_LDAP{instance}'

                # Check if this LDAP instance is configured by looking for SERVER_URI
                server_uri_setting = f'{prefix}_SERVER_URI'
                server_uri = getattr(settings, server_uri_setting, None)

                # Skip this instance if SERVER_URI is not configured or empty
                if not server_uri or server_uri.strip() == '':
                    continue

                config_data = {}
                org_map_value = None
                team_map_value = None

                # Define all LDAP settings we want to collect
                ldap_settings = [
                    'SERVER_URI',
                    'BIND_DN',
                    'BIND_PASSWORD',
                    'START_TLS',
                    'CONNECTION_OPTIONS',
                    'USER_SEARCH',
                    'USER_DN_TEMPLATE',
                    'USER_ATTR_MAP',
                    'GROUP_SEARCH',
                    'GROUP_TYPE',
                    'GROUP_TYPE_PARAMS',
                    'REQUIRE_GROUP',
                    'DENY_GROUP',
                    'USER_FLAGS_BY_GROUP',
                    'ORGANIZATION_MAP',
                    'TEAM_MAP',
                ]

                # Collect all settings for this LDAP instance
                for setting in ldap_settings:
                    setting_name = f'{prefix}_{setting}'
                    value = getattr(settings, setting_name, None)
                    config_data[setting_name] = value

                    # Capture org and team map values for special processing
                    if setting == 'ORGANIZATION_MAP':
                        org_map_value = value
                    elif setting == 'TEAM_MAP':
                        team_map_value = value

                # Convert LDAP org and team mappings from AWX to the Gateway format
                # Start with order 1 and maintain sequence across both org and team mappers
                org_mappers, next_order = org_map_to_gateway_format(org_map_value, start_order=1)
                team_mappers, _ = team_map_to_gateway_format(team_map_value, start_order=next_order)

                # Determine instance name for identification
                instance_name = 'ldap' if instance == '' else f'ldap{instance}'

                found_configs.append({'category': instance_name, 'settings': config_data, 'org_mappers': org_mappers, 'team_mappers': team_mappers})

            except Exception as e:
                instance_name = 'ldap' if instance == '' else f'ldap{instance}'
                raise Exception(f'Could not retrieve {instance_name} settings: {str(e)}')

        return found_configs

    def get_saml_config(self):
        """
        Export SAML authenticators. A SAML authenticator is only exported if
        required configuration is present.

        Returns:
            list: List of configured SAML authentication providers with their settings
        """
        # TODO: Implement SAML configuration retrieval
        # SAML settings typically include:
        # - SOCIAL_AUTH_SAML_SP_ENTITY_ID
        # - SOCIAL_AUTH_SAML_SP_PUBLIC_CERT
        # - SOCIAL_AUTH_SAML_SP_PRIVATE_KEY
        # - SOCIAL_AUTH_SAML_ORG_INFO
        # - SOCIAL_AUTH_SAML_TECHNICAL_CONTACT
        # - SOCIAL_AUTH_SAML_SUPPORT_CONTACT
        # - SOCIAL_AUTH_SAML_ENABLED_IDPS
        # - SOCIAL_AUTH_SAML_ORGANIZATION_MAP
        # - SOCIAL_AUTH_SAML_TEAM_MAP
        found_configs = []
        return found_configs

    def get_google_oauth2_config(self):
        """
        Export Google OAuth2 authenticators. A Google OAuth2 authenticator is only exported if
        KEY and SECRET are configured.

        Returns:
            list: List of configured Google OAuth2 authentication providers with their settings
        """
        # TODO: Implement Google OAuth2 configuration retrieval
        # Google OAuth2 settings typically include:
        # - SOCIAL_AUTH_GOOGLE_OAUTH2_KEY
        # - SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET
        # - SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE
        # - SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS
        # - SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS
        # - SOCIAL_AUTH_GOOGLE_OAUTH2_ORGANIZATION_MAP
        # - SOCIAL_AUTH_GOOGLE_OAUTH2_TEAM_MAP
        found_configs = []
        return found_configs

    def get_azure_ad_config(self):
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

    def get_radius_config(self):
        """
        Export RADIUS authenticators. A RADIUS authenticator is only exported if
        server configuration is present.

        Returns:
            list: List of configured RADIUS authentication providers with their settings
        """
        # TODO: Implement RADIUS configuration retrieval
        # RADIUS settings typically include:
        # - RADIUS_SERVER
        # - RADIUS_PORT
        # - RADIUS_SECRET
        # - RADIUS_NASID
        # - RADIUS_TIMEOUT
        # - RADIUS_RETRIES
        # - RADIUS_GROUP_TYPE
        # - RADIUS_GROUP_TYPE_PARAMS
        # - RADIUS_ORGANIZATION_MAP
        # - RADIUS_TEAM_MAP
        found_configs = []
        return found_configs

    def get_tacacs_plus_config(self):
        """
        Export TACACS+ authenticators. A TACACS+ authenticator is only exported if
        server configuration is present.

        Returns:
            list: List of configured TACACS+ authentication providers with their settings
        """
        # TODO: Implement TACACS+ configuration retrieval
        # TACACS+ settings typically include:
        # - TACACSPLUS_HOST
        # - TACACSPLUS_PORT
        # - TACACSPLUS_SECRET
        # - TACACSPLUS_SESSION_TIMEOUT
        # - TACACSPLUS_AUTH_PROTOCOL
        # - TACACSPLUS_ORGANIZATION_MAP
        # - TACACSPLUS_TEAM_MAP
        found_configs = []
        return found_configs
