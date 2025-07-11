"""
LDAP authenticator migrator.

This module handles the migration of LDAP authenticators from AWX to Gateway.
"""

from django.conf import settings
from awx.main.utils.gateway_mapping import org_map_to_gateway_format, team_map_to_gateway_format, role_map_to_gateway_format
from awx.sso.utils.base_migrator import BaseAuthenticatorMigrator
import ldap


class LDAPMigrator(BaseAuthenticatorMigrator):
    """
    Handles the migration of LDAP authenticators from AWX to Gateway.
    """

    def get_authenticator_type(self):
        """Get the human-readable authenticator type name."""
        return "LDAP"

    def get_controller_config(self):
        """
        Export all LDAP authenticators. An LDAP authenticator is only exported if
        SERVER_URI is configured. Otherwise it will be skipped.

        Returns:
            list: List of configured LDAP authentication providers with their settings
        """
        # AWX supports up to 6 LDAP configurations: AUTH_LDAP (default) and AUTH_LDAP_1 through AUTH_LDAP_5
        ldap_instances = [None, 1, 2, 3, 4, 5]  # None represents the default AUTH_LDAP_ configuration
        found_configs = []

        for instance in ldap_instances:
            # Build the prefix for this LDAP instance
            prefix = f"AUTH_LDAP_{instance}_" if instance is not None else "AUTH_LDAP_"
            category = f"ldap{instance}" if instance is not None else "ldap"

            try:
                # Get all LDAP settings for this instance
                config_data = self._get_ldap_instance_config(prefix)
            except Exception as e:
                raise Exception(f'Could not retrieve {category} settings: {str(e)}')

            # Skip if SERVER_URI is not configured (required for LDAP to function)
            if not config_data.get('SERVER_URI'):
                continue

            # Convert organization, team, and role mappings to Gateway format
            org_map_value = config_data.get('ORGANIZATION_MAP', {})
            team_map_value = config_data.get('TEAM_MAP', {})
            role_map_value = config_data.get('USER_FLAGS_BY_GROUP', {})
            require_group_value = config_data.get('REQUIRE_GROUP', {})
            deny_group_value = config_data.get('DENY_GROUP', {})

            allow_mappers = []

            # Start with order 1 and maintain sequence across org, team, and role mappers
            allow_mappers, next_order = self._ldap_group_allow_to_gateway_format(allow_mappers, deny_group_value, deny=True, start_order=1)
            allow_mappers, next_order = self._ldap_group_allow_to_gateway_format(allow_mappers, require_group_value, deny=False, start_order=next_order)

            org_mappers, next_order = org_map_to_gateway_format(org_map_value, start_order=next_order)
            team_mappers, next_order = team_map_to_gateway_format(team_map_value, start_order=next_order)
            role_mappers, _ = role_map_to_gateway_format(role_map_value, start_order=next_order)

            found_configs.append(
                {
                    'category': category,
                    'settings': config_data,
                    'org_mappers': org_mappers,
                    'team_mappers': team_mappers,
                    'role_mappers': role_mappers,
                    'allow_mappers': allow_mappers,
                }
            )

        return found_configs

    def _get_ldap_instance_config(self, prefix):
        """
        Get all LDAP configuration settings for a specific instance.

        Args:
            prefix: The setting prefix (e.g., 'AUTH_LDAP_' or 'AUTH_LDAP_1_')

        Returns:
            dict: Dictionary of LDAP configuration settings
        """
        # Define all LDAP setting keys
        ldap_keys = [
            'SERVER_URI',  # Required: LDAP server URI(s)
            'BIND_DN',  # Optional: Bind DN for authentication
            'BIND_PASSWORD',  # Optional: Bind password
            'START_TLS',  # Optional: Enable TLS
            'CONNECTION_OPTIONS',  # Optional: LDAP connection options
            'USER_SEARCH',  # Optional: User search configuration
            'USER_DN_TEMPLATE',  # Optional: User DN template
            'USER_ATTR_MAP',  # Optional: User attribute mapping
            'GROUP_SEARCH',  # Optional: Group search configuration
            'GROUP_TYPE',  # Optional: Group type class
            'GROUP_TYPE_PARAMS',  # Optional: Group type parameters
            'REQUIRE_GROUP',  # Optional: Required group DN
            'DENY_GROUP',  # Optional: Denied group DN
            'USER_FLAGS_BY_GROUP',  # Optional: User flags mapping
            'ORGANIZATION_MAP',  # Optional: Organization mapping
            'TEAM_MAP',  # Optional: Team mapping
        ]

        config_data = {}

        for key in ldap_keys:
            setting_name = f"{prefix}{key}"
            value = getattr(settings, setting_name, None)

            # Handle special field types that need conversion
            if key == 'GROUP_TYPE' and value:
                # Convert GROUP_TYPE class to string representation
                config_data[key] = type(value).__name__
            elif key == 'SERVER_URI' and value:
                # Convert SERVER_URI to list format if it's a comma-separated string
                config_data[key] = [uri.strip() for uri in value.split(',')]
            elif key in ['USER_SEARCH', 'GROUP_SEARCH'] and value:
                # Convert LDAPSearch objects to list format [base_dn, scope, filter]
                if hasattr(value, 'base_dn') and hasattr(value, 'filterstr'):
                    # Get the actual scope instead of hardcoding SCOPE_SUBTREE
                    scope = getattr(value, 'scope', ldap.SCOPE_SUBTREE)  # 2 is SCOPE_SUBTREE default
                    scope_name = {ldap.SCOPE_BASE: 'SCOPE_BASE', ldap.SCOPE_ONELEVEL: 'SCOPE_ONELEVEL', ldap.SCOPE_SUBTREE: 'SCOPE_SUBTREE'}.get(
                        scope, 'SCOPE_SUBTREE'
                    )
                    config_data[key] = [value.base_dn, scope_name, value.filterstr]
                else:
                    config_data[key] = value
            elif key in ['USER_ATTR_MAP', 'GROUP_TYPE_PARAMS', 'USER_FLAGS_BY_GROUP', 'ORGANIZATION_MAP', 'TEAM_MAP']:
                # Ensure dict fields are properly handled
                config_data[key] = value if value is not None else {}
            elif key == 'CONNECTION_OPTIONS' and value:
                # CONNECTION_OPTIONS is a dict of LDAP options
                config_data[key] = value if value is not None else {}
            else:
                # Store the value as-is for other fields
                config_data[key] = value

        return config_data

    def create_gateway_authenticator(self, config):
        """Create an LDAP authenticator in Gateway."""
        category = config['category']
        settings = config['settings']

        # Extract the first server URI for slug generation
        authenticator_slug = self._generate_authenticator_slug('ldap', category)

        # Build the gateway payload
        gateway_config = {
            'name': category,
            'slug': authenticator_slug,
            'type': 'ansible_base.authentication.authenticator_plugins.ldap',
            'create_objects': True,
            'remove_users': False,
            'enabled': True,
            'configuration': self._build_ldap_configuration(settings),
        }

        self._write_output(f'Creating LDAP authenticator: {gateway_config["name"]}')

        # LDAP authenticators have auto-generated fields that should be ignored during comparison
        # BIND_PASSWORD - encrypted value, can't be compared
        ignore_keys = ['BIND_PASSWORD']

        # Submit the authenticator using the base class method
        return self.submit_authenticator(gateway_config, config=config, ignore_keys=ignore_keys)

    def _build_ldap_configuration(self, settings):
        """Build the LDAP configuration section for Gateway."""
        config = {}

        # Server URI is required
        if settings.get('SERVER_URI'):
            config['SERVER_URI'] = settings['SERVER_URI']

        # Authentication settings
        if settings.get('BIND_DN'):
            config['BIND_DN'] = settings['BIND_DN']
        if settings.get('BIND_PASSWORD'):
            config['BIND_PASSWORD'] = settings['BIND_PASSWORD']

        # TLS settings
        if settings.get('START_TLS') is not None:
            config['START_TLS'] = settings['START_TLS']

        # User search configuration
        if settings.get('USER_SEARCH'):
            config['USER_SEARCH'] = settings['USER_SEARCH']

        # User attribute mapping
        if settings.get('USER_ATTR_MAP'):
            config['USER_ATTR_MAP'] = settings['USER_ATTR_MAP']

        # Group search configuration
        if settings.get('GROUP_SEARCH'):
            config['GROUP_SEARCH'] = settings['GROUP_SEARCH']

        # Group type and parameters
        if settings.get('GROUP_TYPE'):
            config['GROUP_TYPE'] = settings['GROUP_TYPE']
        if settings.get('GROUP_TYPE_PARAMS'):
            config['GROUP_TYPE_PARAMS'] = settings['GROUP_TYPE_PARAMS']

        # Connection options - convert numeric LDAP constants to string keys
        if settings.get('CONNECTION_OPTIONS'):
            config['CONNECTION_OPTIONS'] = self._convert_ldap_connection_options(settings['CONNECTION_OPTIONS'])

        # User DN template
        if settings.get('USER_DN_TEMPLATE'):
            config['USER_DN_TEMPLATE'] = settings['USER_DN_TEMPLATE']

        # REQUIRE_GROUP and DENY_GROUP are handled as allow mappers, not included in config
        # USER_FLAGS_BY_GROUP is handled as role mappers, not included in config

        return config

    def _convert_ldap_connection_options(self, connection_options):
        """
        Convert numeric LDAP connection option constants to their string representations.
        Uses the actual constants from the python-ldap library.

        Args:
            connection_options: Dictionary with numeric LDAP option keys

        Returns:
            dict: Dictionary with string LDAP option keys
        """
        # Comprehensive mapping using LDAP constants as keys
        ldap_option_map = {
            # Basic LDAP options
            ldap.OPT_API_INFO: 'OPT_API_INFO',
            ldap.OPT_DEREF: 'OPT_DEREF',
            ldap.OPT_SIZELIMIT: 'OPT_SIZELIMIT',
            ldap.OPT_TIMELIMIT: 'OPT_TIMELIMIT',
            ldap.OPT_REFERRALS: 'OPT_REFERRALS',
            ldap.OPT_RESULT_CODE: 'OPT_RESULT_CODE',
            ldap.OPT_ERROR_NUMBER: 'OPT_ERROR_NUMBER',
            ldap.OPT_RESTART: 'OPT_RESTART',
            ldap.OPT_PROTOCOL_VERSION: 'OPT_PROTOCOL_VERSION',
            ldap.OPT_SERVER_CONTROLS: 'OPT_SERVER_CONTROLS',
            ldap.OPT_CLIENT_CONTROLS: 'OPT_CLIENT_CONTROLS',
            ldap.OPT_API_FEATURE_INFO: 'OPT_API_FEATURE_INFO',
            ldap.OPT_HOST_NAME: 'OPT_HOST_NAME',
            ldap.OPT_DESC: 'OPT_DESC',
            ldap.OPT_DIAGNOSTIC_MESSAGE: 'OPT_DIAGNOSTIC_MESSAGE',
            ldap.OPT_ERROR_STRING: 'OPT_ERROR_STRING',
            ldap.OPT_MATCHED_DN: 'OPT_MATCHED_DN',
            ldap.OPT_DEBUG_LEVEL: 'OPT_DEBUG_LEVEL',
            ldap.OPT_TIMEOUT: 'OPT_TIMEOUT',
            ldap.OPT_REFHOPLIMIT: 'OPT_REFHOPLIMIT',
            ldap.OPT_NETWORK_TIMEOUT: 'OPT_NETWORK_TIMEOUT',
            ldap.OPT_URI: 'OPT_URI',
            # TLS options
            ldap.OPT_X_TLS: 'OPT_X_TLS',
            ldap.OPT_X_TLS_CTX: 'OPT_X_TLS_CTX',
            ldap.OPT_X_TLS_CACERTFILE: 'OPT_X_TLS_CACERTFILE',
            ldap.OPT_X_TLS_CACERTDIR: 'OPT_X_TLS_CACERTDIR',
            ldap.OPT_X_TLS_CERTFILE: 'OPT_X_TLS_CERTFILE',
            ldap.OPT_X_TLS_KEYFILE: 'OPT_X_TLS_KEYFILE',
            ldap.OPT_X_TLS_REQUIRE_CERT: 'OPT_X_TLS_REQUIRE_CERT',
            ldap.OPT_X_TLS_CIPHER_SUITE: 'OPT_X_TLS_CIPHER_SUITE',
            ldap.OPT_X_TLS_RANDOM_FILE: 'OPT_X_TLS_RANDOM_FILE',
            ldap.OPT_X_TLS_DHFILE: 'OPT_X_TLS_DHFILE',
            ldap.OPT_X_TLS_NEVER: 'OPT_X_TLS_NEVER',
            ldap.OPT_X_TLS_HARD: 'OPT_X_TLS_HARD',
            ldap.OPT_X_TLS_DEMAND: 'OPT_X_TLS_DEMAND',
            ldap.OPT_X_TLS_ALLOW: 'OPT_X_TLS_ALLOW',
            ldap.OPT_X_TLS_TRY: 'OPT_X_TLS_TRY',
            ldap.OPT_X_TLS_CRL_NONE: 'OPT_X_TLS_CRL_NONE',
            ldap.OPT_X_TLS_CRL_PEER: 'OPT_X_TLS_CRL_PEER',
            ldap.OPT_X_TLS_CRL_ALL: 'OPT_X_TLS_CRL_ALL',
            # SASL options
            ldap.OPT_X_SASL_MECH: 'OPT_X_SASL_MECH',
            ldap.OPT_X_SASL_REALM: 'OPT_X_SASL_REALM',
            ldap.OPT_X_SASL_AUTHCID: 'OPT_X_SASL_AUTHCID',
            ldap.OPT_X_SASL_AUTHZID: 'OPT_X_SASL_AUTHZID',
            ldap.OPT_X_SASL_SSF: 'OPT_X_SASL_SSF',
            ldap.OPT_X_SASL_SSF_EXTERNAL: 'OPT_X_SASL_SSF_EXTERNAL',
            ldap.OPT_X_SASL_SECPROPS: 'OPT_X_SASL_SECPROPS',
            ldap.OPT_X_SASL_SSF_MIN: 'OPT_X_SASL_SSF_MIN',
            ldap.OPT_X_SASL_SSF_MAX: 'OPT_X_SASL_SSF_MAX',
        }

        # Add optional options that may not be available in all versions
        optional_options = [
            'OPT_TCP_USER_TIMEOUT',
            'OPT_DEFBASE',
            'OPT_X_TLS_VERSION',
            'OPT_X_TLS_CIPHER',
            'OPT_X_TLS_PEERCERT',
            'OPT_X_TLS_CRLCHECK',
            'OPT_X_TLS_CRLFILE',
            'OPT_X_TLS_NEWCTX',
            'OPT_X_TLS_PROTOCOL_MIN',
            'OPT_X_TLS_PACKAGE',
            'OPT_X_TLS_ECNAME',
            'OPT_X_TLS_REQUIRE_SAN',
            'OPT_X_TLS_PROTOCOL_MAX',
            'OPT_X_TLS_PROTOCOL_SSL3',
            'OPT_X_TLS_PROTOCOL_TLS1_0',
            'OPT_X_TLS_PROTOCOL_TLS1_1',
            'OPT_X_TLS_PROTOCOL_TLS1_2',
            'OPT_X_TLS_PROTOCOL_TLS1_3',
            'OPT_X_SASL_NOCANON',
            'OPT_X_SASL_USERNAME',
            'OPT_CONNECT_ASYNC',
            'OPT_X_KEEPALIVE_IDLE',
            'OPT_X_KEEPALIVE_PROBES',
            'OPT_X_KEEPALIVE_INTERVAL',
        ]

        for option_name in optional_options:
            if hasattr(ldap, option_name):
                ldap_option_map[getattr(ldap, option_name)] = option_name

        converted_options = {}

        for key, value in connection_options.items():
            if key in ldap_option_map:
                converted_options[ldap_option_map[key]] = value

        return converted_options

    def _ldap_group_allow_to_gateway_format(self, result: list, ldap_group: str, deny=False, start_order=1):
        """Convert an LDAP require or deny group to a Gateway mapper

        Args:
            result: array to append the mapper to
            ldap_group: An LDAP group query
            deny: Whether the mapper denies or requires users to be in the group
            start_order: Starting order value for the mappers

        Returns:
            tuple: (List of Gateway-compatible organization mappers, next_order)
        """
        if ldap_group is None:
            return result, start_order

        if deny:
            result.append(
                {
                    "name": "LDAP-DenyGroup",
                    "authenticator": -1,
                    "map_type": "allow",
                    "revoke": True,
                    "triggers": {"groups": {"has_or": [ldap_group]}},
                    "order": start_order,
                }
            )
        else:
            result.append(
                {
                    "name": "LDAP-RequireGroup",
                    "authenticator": -1,
                    "map_type": "allow",
                    "revoke": False,
                    "triggers": {"groups": {"has_and": [ldap_group]}},
                    "order": start_order,
                }
            )

        return result, start_order + 1
