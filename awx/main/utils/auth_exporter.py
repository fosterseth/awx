"""
Authentication configuration exporter for AAP Gateway.

This module handles the conversion and export of AWX authentication
configurations to AAP Gateway via REST API calls.
"""

import re
import hashlib
from awx.main.utils.gateway_client import GatewayClient, GatewayAPIError


class AuthConfigExporter:
    """
    Handles the export of authentication configurations from AWX to Gateway.
    Converts AWX configurations to Gateway format and creates authenticators and mappers.
    """

    def __init__(self, gateway_client: GatewayClient, command=None):
        """
        Initialize the auth config exporter.

        Args:
            gateway_client: GatewayClient instance for API calls
            command: Optional Django management command instance (for styled output)
        """
        self.gateway_client = gateway_client
        self.command = command

    def export_configs(self, auth_configs, config_type='github'):
        """
        Export a list of authentication configurations to Gateway.

        Args:
            auth_configs: List of authentication configurations from AuthConfigMigrator
            config_type: Type of configuration ('github', 'ldap', etc.)

        Returns:
            dict: Summary of export results
        """
        if not auth_configs:
            self._write_output(f'No {config_type} authenticators found to migrate.', 'warning')
            return {'created': 0, 'failed': 0, 'mappers_created': 0, 'mappers_failed': 0}

        self._write_output(f'Found {len(auth_configs)} {config_type} authentication configuration(s).', 'success')

        # Process each authenticator configuration
        created_authenticators = []
        for config in auth_configs:
            if self._create_gateway_authenticator(config, config_type):
                created_authenticators.append(config)

        # Create mappers for successfully created authenticators
        mappers_created = 0
        mappers_failed = 0
        if created_authenticators:
            self._write_output('\n=== Creating Authenticator Mappers ===', 'success')
            for config in created_authenticators:
                mapper_result = self._create_gateway_mappers(config)
                mappers_created += mapper_result['created']
                mappers_failed += mapper_result['failed']

        return {
            'created': len(created_authenticators),
            'failed': len(auth_configs) - len(created_authenticators),
            'mappers_created': mappers_created,
            'mappers_failed': mappers_failed,
        }

    def _create_gateway_authenticator(self, config, config_type):
        """Create a single authenticator in Gateway from AWX config.

        Args:
            config: AWX authenticator configuration dict
            config_type: Type of configuration ('github', 'ldap', etc.)

        Returns:
            bool: True if authenticator was created successfully, False otherwise
        """
        category = config['category']
        settings = config['settings']

        # Handle different config types
        if config_type == 'github':
            return self._create_github_authenticator(config, category, settings)
        elif config_type == 'ldap':
            return self._create_ldap_authenticator(config, category, settings)
        elif config_type == 'saml':
            return self._create_saml_authenticator(config, category, settings)
        elif config_type == 'google_oauth2':
            return self._create_google_oauth2_authenticator(config, category, settings)
        elif config_type == 'azure_ad':
            return self._create_azure_ad_authenticator(config, category, settings)
        elif config_type == 'radius':
            return self._create_radius_authenticator(config, category, settings)
        elif config_type == 'tacacs_plus':
            return self._create_tacacs_plus_authenticator(config, category, settings)
        else:
            self._write_output(f'Unknown config type {config_type}, skipping', 'warning')
            return False

    def _create_github_authenticator(self, config, category, settings):
        """Create a GitHub authenticator in Gateway."""
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
        authenticator_name = f"AWX-{category.replace('-', '_').title()}"
        authenticator_slug = self._generate_authenticator_slug('github', category, key_value)

        # Map AWX category to Gateway authenticator type
        type_mapping = {
            'github': 'ansible_base.authentication.authenticator_plugins.github',
            'github-org': 'ansible_base.authentication.authenticator_plugins.github_org',
            'github-team': 'ansible_base.authentication.authenticator_plugins.github_team',
            'github-enterprise': 'ansible_base.authentication.authenticator_plugins.github_enterprise',
            'github-enterprise-org': 'ansible_base.authentication.authenticator_plugins.github_enterprise_org',
            'github-enterprise-team': 'ansible_base.authentication.authenticator_plugins.github_enterprise_team',
            'oidc': 'ansible_base.authentication.authenticator_plugins.oidc',
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

        try:
            # Check if authenticator already exists by slug
            existing_authenticators = self.gateway_client.get_authenticators()
            existing_authenticator = None

            for auth in existing_authenticators:
                if auth.get('slug') == authenticator_slug:
                    existing_authenticator = auth
                    break

            if existing_authenticator:
                # Authenticator already exists, use it
                authenticator_id = existing_authenticator.get('id')
                self._write_output(f'⚠ Authenticator already exists with ID: {authenticator_id}', 'warning')

                # Store the existing result for mapper creation
                config['gateway_authenticator_id'] = authenticator_id
                config['gateway_authenticator'] = existing_authenticator
                return True
            else:
                # Authenticator doesn't exist, create it
                self._write_output('Creating new authenticator...')

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

                # Create the authenticator
                result = self.gateway_client.create_authenticator(gateway_config)

                self._write_output(f'✓ Successfully created authenticator with ID: {result.get("id")}', 'success')

                # Store the result for potential mapper creation later
                config['gateway_authenticator_id'] = result.get('id')
                config['gateway_authenticator'] = result
                return True

        except GatewayAPIError as e:
            self._write_output(f'✗ Failed to create {category} authenticator: {e.message}', 'error')
            if e.response_data:
                self._write_output(f'  Details: {e.response_data}', 'error')
            return False
        except Exception as e:
            self._write_output(f'✗ Unexpected error creating {category} authenticator: {str(e)}', 'error')
            return False

    def _create_ldap_authenticator(self, config, category, settings):
        """Create an LDAP authenticator in Gateway."""
        # Extract the LDAP server URI as the identifier
        server_uri = None
        for setting_name, value in settings.items():
            if setting_name.endswith('_SERVER_URI') and value:
                server_uri = value
                break

        if not server_uri:
            self._write_output(f'Skipping {category}: missing LDAP server URI', 'warning')
            return False

        # Generate authenticator name and slug
        authenticator_name = f"AWX-{category.replace('_', '-').title()}"
        authenticator_slug = self._generate_authenticator_slug('ldap', category, server_uri)

        # Get LDAP authenticator type
        authenticator_type = 'ansible_base.authentication.authenticator_plugins.ldap'

        self._write_output(f'\n--- Processing {category} authenticator ---')
        self._write_output(f'Name: {authenticator_name}')
        self._write_output(f'Slug: {authenticator_slug}')
        self._write_output(f'Type: {authenticator_type}')
        self._write_output(f'Server URI: {server_uri}')

        try:
            # Check if authenticator already exists by slug
            existing_authenticators = self.gateway_client.get_authenticators()
            existing_authenticator = None

            for auth in existing_authenticators:
                if auth.get('slug') == authenticator_slug:
                    existing_authenticator = auth
                    break

            if existing_authenticator:
                # Authenticator already exists, use it
                authenticator_id = existing_authenticator.get('id')
                self._write_output(f'⚠ Authenticator already exists with ID: {authenticator_id}', 'warning')

                # Store the existing result for mapper creation
                config['gateway_authenticator_id'] = authenticator_id
                config['gateway_authenticator'] = existing_authenticator
                return True
            else:
                # Authenticator doesn't exist, create it
                self._write_output('Creating new LDAP authenticator...')

                # Build Gateway LDAP authenticator configuration
                gateway_config = {
                    "name": authenticator_name,
                    "slug": authenticator_slug,
                    "type": authenticator_type,
                    "enabled": True,
                    "create_objects": True,  # Allow Gateway to create users/orgs/teams
                    "remove_users": False,  # Don't remove users by default
                    "configuration": self._build_ldap_configuration(settings),
                }

                # Create the authenticator
                result = self.gateway_client.create_authenticator(gateway_config)

                self._write_output(f'✓ Successfully created LDAP authenticator with ID: {result.get("id")}', 'success')

                # Store the result for potential mapper creation later
                config['gateway_authenticator_id'] = result.get('id')
                config['gateway_authenticator'] = result
                return True

        except GatewayAPIError as e:
            self._write_output(f'✗ Failed to create {category} authenticator: {e.message}', 'error')
            if e.response_data:
                self._write_output(f'  Details: {e.response_data}', 'error')
            return False
        except Exception as e:
            self._write_output(f'✗ Unexpected error creating {category} authenticator: {str(e)}', 'error')
            return False

    def _create_saml_authenticator(self, config, category, settings):
        """Create a SAML authenticator in Gateway."""
        # TODO: Implement SAML authenticator creation
        # When implementing, use this pattern for slug generation:
        # entity_id = settings.get('SOCIAL_AUTH_SAML_SP_ENTITY_ID', 'saml')
        # authenticator_slug = self._generate_authenticator_slug('saml', category, entity_id)
        # SAML requires complex configuration including:
        # - SP entity ID, certificates, metadata
        # - IdP configuration and metadata
        # - Attribute mapping
        self._write_output(f'SAML authenticator creation not yet implemented for {category}', 'warning')
        return False

    def _create_google_oauth2_authenticator(self, config, category, settings):
        """Create a Google OAuth2 authenticator in Gateway."""
        # TODO: Implement Google OAuth2 authenticator creation
        # When implementing, use this pattern for slug generation:
        # client_id = settings.get('SOCIAL_AUTH_GOOGLE_OAUTH2_KEY', 'google')
        # authenticator_slug = self._generate_authenticator_slug('google_oauth2', category, client_id)
        # Similar to GitHub OAuth2 but with Google-specific endpoints
        # - Extract GOOGLE_OAUTH2_KEY and GOOGLE_OAUTH2_SECRET
        # - Handle whitelisted domains/emails
        # - Configure Google OAuth2 scope
        self._write_output(f'Google OAuth2 authenticator creation not yet implemented for {category}', 'warning')
        return False

    def _create_azure_ad_authenticator(self, config, category, settings):
        """Create an Azure AD authenticator in Gateway."""
        # TODO: Implement Azure AD authenticator creation
        # When implementing, use this pattern for slug generation:
        # client_id = settings.get('SOCIAL_AUTH_AZUREAD_OAUTH2_KEY', 'azure')
        # authenticator_slug = self._generate_authenticator_slug('azure_ad', category, client_id)
        # Azure AD requires:
        # - Application ID and secret
        # - Tenant ID (for tenant-specific auth)
        # - Proper OAuth2 endpoints for Azure
        self._write_output(f'Azure AD authenticator creation not yet implemented for {category}', 'warning')
        return False

    def _create_radius_authenticator(self, config, category, settings):
        """Create a RADIUS authenticator in Gateway."""
        # TODO: Implement RADIUS authenticator creation
        # When implementing, use this pattern for slug generation:
        # server_host = settings.get('RADIUS_SERVER', 'radius')
        # authenticator_slug = self._generate_authenticator_slug('radius', category, server_host)
        # RADIUS is a different authentication protocol than OAuth2/SAML
        # - Server host and port
        # - Shared secret
        # - NAS identifier
        # - Timeout and retry settings
        self._write_output(f'RADIUS authenticator creation not yet implemented for {category}', 'warning')
        return False

    def _create_tacacs_plus_authenticator(self, config, category, settings):
        """Create a TACACS+ authenticator in Gateway."""
        # TODO: Implement TACACS+ authenticator creation
        # When implementing, use this pattern for slug generation:
        # server_host = settings.get('TACACSPLUS_HOST', 'tacacs')
        # authenticator_slug = self._generate_authenticator_slug('tacacs_plus', category, server_host)
        # TACACS+ is a Cisco-developed authentication protocol
        # - Server host and port
        # - Shared secret
        # - Authentication protocol settings
        # - Session timeout
        self._write_output(f'TACACS+ authenticator creation not yet implemented for {category}', 'warning')
        return False

    def _build_additional_config(self, category, settings):
        """Build additional configuration for specific authenticator types.

        Args:
            category: AWX category (github, github-org, etc.)
            settings: AWX settings dictionary

        Returns:
            dict: Additional configuration parameters
        """
        additional_config = {}

        # Add scope configuration if present
        for setting_name, value in settings.items():
            if setting_name.endswith('_SCOPE') and value:
                additional_config['SCOPE'] = value
                break

        # Add GitHub Enterprise URL if present
        if 'enterprise' in category:
            for setting_name, value in settings.items():
                if setting_name.endswith('_URL') and value:
                    additional_config['URL'] = value
                elif setting_name.endswith('_API_URL') and value:
                    additional_config['API_URL'] = value

        # Add organization name for org-specific authenticators
        if 'org' in category:
            for setting_name, value in settings.items():
                if setting_name.endswith('_NAME') and value:
                    additional_config['ORG_NAME'] = value
                    break

        # Add team ID for team-specific authenticators
        if 'team' in category:
            for setting_name, value in settings.items():
                if setting_name.endswith('_ID') and value:
                    additional_config['TEAM_ID'] = value
                    break

        # Add OIDC endpoint for generic OIDC
        if category == 'oidc':
            for setting_name, value in settings.items():
                if setting_name.endswith('_OIDC_ENDPOINT') and value:
                    additional_config['OIDC_ENDPOINT'] = value
                elif setting_name.endswith('_VERIFY_SSL') and value is not None:
                    additional_config['VERIFY_SSL'] = value

        return additional_config

    def _build_ldap_configuration(self, settings):
        """Build LDAP configuration for Gateway from AWX settings.

        Args:
            settings: AWX LDAP settings dictionary

        Returns:
            dict: Gateway-compatible LDAP configuration
        """
        config = {}

        # Required settings
        for setting_name, value in settings.items():
            if setting_name.endswith('_SERVER_URI') and value:
                # Gateway expects SERVER_URI as a list
                config['SERVER_URI'] = [value] if isinstance(value, str) else value
            elif setting_name.endswith('_BIND_DN') and value:
                config['BIND_DN'] = value
            elif setting_name.endswith('_BIND_PASSWORD') and value:
                config['BIND_PASSWORD'] = value
            elif setting_name.endswith('_START_TLS') and value is not None:
                config['START_TLS'] = bool(value)

        # User search configuration
        for setting_name, value in settings.items():
            if setting_name.endswith('_USER_SEARCH') and value:
                # AWX stores USER_SEARCH as a tuple/list like (base_dn, scope, filter)
                if isinstance(value, (list, tuple)) and len(value) >= 3:
                    config['USER_SEARCH'] = [value[0], value[1], value[2]]

        # User attribute mapping
        for setting_name, value in settings.items():
            if setting_name.endswith('_USER_ATTR_MAP') and value:
                config['USER_ATTR_MAP'] = value

        # Group search configuration
        for setting_name, value in settings.items():
            if setting_name.endswith('_GROUP_SEARCH') and value:
                # AWX stores GROUP_SEARCH as a tuple/list like (base_dn, scope, filter)
                if isinstance(value, (list, tuple)) and len(value) >= 3:
                    config['GROUP_SEARCH'] = [value[0], value[1], value[2]]

        # Group type configuration
        for setting_name, value in settings.items():
            if setting_name.endswith('_GROUP_TYPE') and value:
                # Convert AWX group type class to string if needed
                if hasattr(value, '__name__'):
                    config['GROUP_TYPE'] = value.__name__
                else:
                    config['GROUP_TYPE'] = str(value)
            elif setting_name.endswith('_GROUP_TYPE_PARAMS') and value:
                config['GROUP_TYPE_PARAMS'] = value

        # Connection options
        for setting_name, value in settings.items():
            if setting_name.endswith('_CONNECTION_OPTIONS') and value:
                config['CONNECTION_OPTIONS'] = value

        # Other LDAP settings
        for setting_name, value in settings.items():
            if setting_name.endswith('_USER_DN_TEMPLATE') and value:
                config['USER_DN_TEMPLATE'] = value
            elif setting_name.endswith('_REQUIRE_GROUP') and value:
                config['REQUIRE_GROUP'] = value
            elif setting_name.endswith('_DENY_GROUP') and value:
                config['DENY_GROUP'] = value
            elif setting_name.endswith('_USER_FLAGS_BY_GROUP') and value:
                config['USER_FLAGS_BY_GROUP'] = value

        return config

    def _generate_authenticator_slug(self, auth_type, category, identifier):
        """Generate a deterministic slug for an authenticator.

        Args:
            auth_type: Type of authenticator ('github', 'ldap', etc.)
            category: AWX category (github, github-org, ldap, etc.)
            identifier: Unique identifier (client ID, server URI, etc.)

        Returns:
            str: Deterministic slug for the authenticator
        """
        # Create a base string from the components
        base_string = f"awx-{auth_type}-{category}-{identifier}"

        # Clean the string: lowercase, replace non-alphanumeric with hyphens
        cleaned = re.sub(r'[^a-zA-Z0-9]+', '-', base_string.lower())

        # Remove leading/trailing hyphens and ensure no double hyphens
        cleaned = re.sub(r'^-+|-+$', '', cleaned)
        cleaned = re.sub(r'-+', '-', cleaned)

        # Generate a hash of the cleaned string for consistent length
        slug_hash = hashlib.md5(cleaned.encode('utf-8')).hexdigest()[:8]

        # Combine type and hash for the final slug
        final_slug = f"awx-{auth_type}-{slug_hash}"

        return final_slug

    def _create_gateway_mappers(self, config):
        """Create authenticator mappers in Gateway from AWX config.

        Args:
            config: AWX authenticator configuration dict with gateway_authenticator_id

        Returns:
            dict: Summary with 'created' and 'failed' counts
        """
        authenticator_id = config.get('gateway_authenticator_id')
        if not authenticator_id:
            self._write_output(f'No authenticator ID found for {config["category"]}, skipping mappers', 'error')
            return {'created': 0, 'failed': 0}

        category = config['category']
        org_mappers = config.get('org_mappers', [])
        team_mappers = config.get('team_mappers', [])

        total_mappers = len(org_mappers) + len(team_mappers)
        if total_mappers == 0:
            self._write_output(f'No mappers to create for {category} authenticator')
            return {'created': 0, 'failed': 0}

        self._write_output(f'\n--- Creating mappers for {category} authenticator (ID: {authenticator_id}) ---')
        self._write_output(f'Organization mappers: {len(org_mappers)}')
        self._write_output(f'Team mappers: {len(team_mappers)}')

        created_count = 0
        failed_count = 0

        # Create organization mappers
        for mapper in org_mappers:
            if self._create_single_mapper(authenticator_id, mapper, 'organization'):
                created_count += 1
            else:
                failed_count += 1

        # Create team mappers
        for mapper in team_mappers:
            if self._create_single_mapper(authenticator_id, mapper, 'team'):
                created_count += 1
            else:
                failed_count += 1

        # Summary
        self._write_output(f'Mappers created: {created_count}, failed: {failed_count}')
        return {'created': created_count, 'failed': failed_count}

    def _create_single_mapper(self, authenticator_id, mapper_config, mapper_type):
        """Create a single mapper in Gateway.

        Args:
            authenticator_id: ID of the authenticator to create mapper for
            mapper_config: Mapper configuration dictionary
            mapper_type: Type of mapper ('organization' or 'team')

        Returns:
            bool: True if mapper was created successfully, False otherwise
        """
        try:
            # Update the mapper config with the correct authenticator ID
            mapper_config = mapper_config.copy()  # Don't modify the original
            mapper_config['authenticator'] = authenticator_id

            # Create the mapper
            self.gateway_client.create_authenticator_map(authenticator_id, mapper_config)

            mapper_name = mapper_config.get('name', 'Unknown')
            self._write_output(f'  ✓ Created {mapper_type} mapper: {mapper_name}', 'success')
            return True

        except GatewayAPIError as e:
            mapper_name = mapper_config.get('name', 'Unknown')
            self._write_output(f'  ✗ Failed to create {mapper_type} mapper "{mapper_name}": {e.message}', 'error')
            if e.response_data:
                self._write_output(f'    Details: {e.response_data}', 'error')
            return False
        except Exception as e:
            mapper_name = mapper_config.get('name', 'Unknown')
            self._write_output(f'  ✗ Unexpected error creating {mapper_type} mapper "{mapper_name}": {str(e)}', 'error')
            return False

    def _write_output(self, message, style=None):
        """Write output message if command is available."""
        if self.command:
            if style == 'success':
                self.command.stdout.write(self.command.style.SUCCESS(message))
            elif style == 'warning':
                self.command.stdout.write(self.command.style.WARNING(message))
            elif style == 'error':
                self.command.stdout.write(self.command.style.ERROR(message))
            else:
                self.command.stdout.write(message)
