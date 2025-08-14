"""
Unit tests for LDAP authenticator migrator.
"""

import ldap
from unittest.mock import Mock, patch
from awx.sso.utils.ldap_migrator import LDAPMigrator


class TestLDAPMigrator:
    """Tests for LDAPMigrator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.gateway_client = Mock()
        self.command = Mock()
        self.migrator = LDAPMigrator(self.gateway_client, self.command)

    def test_get_authenticator_type(self):
        """Test that get_authenticator_type returns 'LDAP'."""
        assert self.migrator.get_authenticator_type() == "LDAP"

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_get_controller_config_no_server_uri(self, mock_settings):
        """Test that LDAP configs without SERVER_URI are skipped."""
        # Mock settings to return None for SERVER_URI
        mock_settings.AUTH_LDAP_SERVER_URI = None
        mock_settings.AUTH_LDAP_1_SERVER_URI = None

        # Mock all other required attributes to avoid AttributeError
        for i in [None, 1, 2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_" if i is not None else "AUTH_LDAP_"
            for key in [
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
            ]:
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()
        assert result == []

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_get_controller_config_with_server_uri(self, mock_settings):
        """Test that LDAP config with SERVER_URI is processed."""
        # Mock basic LDAP configuration
        mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
        mock_settings.AUTH_LDAP_BIND_DN = "cn=admin,dc=example,dc=com"
        mock_settings.AUTH_LDAP_BIND_PASSWORD = "password"
        mock_settings.AUTH_LDAP_START_TLS = False
        mock_settings.AUTH_LDAP_CONNECTION_OPTIONS = {}
        mock_settings.AUTH_LDAP_USER_SEARCH = None
        mock_settings.AUTH_LDAP_USER_DN_TEMPLATE = None
        mock_settings.AUTH_LDAP_USER_ATTR_MAP = {}
        mock_settings.AUTH_LDAP_GROUP_SEARCH = None
        mock_settings.AUTH_LDAP_GROUP_TYPE = None
        mock_settings.AUTH_LDAP_GROUP_TYPE_PARAMS = {}
        mock_settings.AUTH_LDAP_REQUIRE_GROUP = None
        mock_settings.AUTH_LDAP_DENY_GROUP = None
        mock_settings.AUTH_LDAP_USER_FLAGS_BY_GROUP = {}
        mock_settings.AUTH_LDAP_ORGANIZATION_MAP = {}
        mock_settings.AUTH_LDAP_TEAM_MAP = {}

        # Mock all other instances to return None for SERVER_URI
        for i in [1, 2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_"
            setattr(mock_settings, f"{prefix}SERVER_URI", None)
            for key in [
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
            ]:
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()

        assert len(result) == 1
        config = result[0]
        assert config['category'] == 'ldap'
        assert config['settings']['SERVER_URI'] == ['ldap://ldap.example.com']
        assert config['settings']['BIND_DN'] == "cn=admin,dc=example,dc=com"
        assert 'org_mappers' in config
        assert 'team_mappers' in config
        assert 'role_mappers' in config
        assert 'allow_mappers' in config

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_get_controller_config_multiple_instances(self, mock_settings):
        """Test processing multiple LDAP instances."""
        # Mock two LDAP instances
        mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap1.example.com"
        mock_settings.AUTH_LDAP_1_SERVER_URI = "ldap://ldap2.example.com"

        # Mock all required attributes for both instances
        for prefix in ["AUTH_LDAP_", "AUTH_LDAP_1_"]:
            for key in [
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
            ]:
                setattr(mock_settings, f"{prefix}{key}", None)

        # Mock remaining instances to return None
        for i in [2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_"
            setattr(mock_settings, f"{prefix}SERVER_URI", None)
            for key in [
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
            ]:
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()

        assert len(result) == 2
        assert result[0]['category'] == 'ldap'
        assert result[1]['category'] == 'ldap'
        assert result[0]['settings']['SERVER_URI'] == ['ldap://ldap1.example.com']
        assert result[1]['settings']['SERVER_URI'] == ['ldap://ldap2.example.com']

    def test_get_ldap_instance_config_basic(self):
        """Test _get_ldap_instance_config with basic settings."""
        with patch('awx.sso.utils.ldap_migrator.settings') as mock_settings:
            mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
            mock_settings.AUTH_LDAP_BIND_DN = "cn=admin,dc=example,dc=com"
            mock_settings.AUTH_LDAP_BIND_PASSWORD = "password"
            mock_settings.AUTH_LDAP_START_TLS = True

            # Mock all other settings to None
            for key in [
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
            ]:
                setattr(mock_settings, f"AUTH_LDAP_{key}", None)

            result = self.migrator._get_ldap_instance_config("AUTH_LDAP_")

            assert result['SERVER_URI'] == ['ldap://ldap.example.com']
            assert result['BIND_DN'] == "cn=admin,dc=example,dc=com"
            assert result['BIND_PASSWORD'] == "password"
            assert result['START_TLS'] is True

    def test_get_ldap_instance_config_server_uri_list(self):
        """Test SERVER_URI conversion from comma-separated string to list."""
        with patch('awx.sso.utils.ldap_migrator.settings') as mock_settings:
            mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap1.example.com, ldap://ldap2.example.com"

            # Mock all other settings to None
            for key in [
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
            ]:
                setattr(mock_settings, f"AUTH_LDAP_{key}", None)

            result = self.migrator._get_ldap_instance_config("AUTH_LDAP_")

            assert result['SERVER_URI'] == ['ldap://ldap1.example.com', 'ldap://ldap2.example.com']

    def test_get_ldap_instance_config_user_search(self):
        """Test USER_SEARCH conversion from LDAPSearch object."""
        with patch('awx.sso.utils.ldap_migrator.settings') as mock_settings:
            # Mock LDAPSearch object
            mock_search = Mock()
            mock_search.base_dn = "ou=users,dc=example,dc=com"
            mock_search.filterstr = "(uid=%(user)s)"
            mock_search.scope = ldap.SCOPE_SUBTREE

            mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
            mock_settings.AUTH_LDAP_USER_SEARCH = mock_search

            # Mock all other settings to None
            for key in [
                'BIND_DN',
                'BIND_PASSWORD',
                'START_TLS',
                'CONNECTION_OPTIONS',
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
            ]:
                setattr(mock_settings, f"AUTH_LDAP_{key}", None)

            result = self.migrator._get_ldap_instance_config("AUTH_LDAP_")

            assert result['USER_SEARCH'] == ["ou=users,dc=example,dc=com", "SCOPE_SUBTREE", "(uid=%(user)s)"]

    def test_get_ldap_instance_config_group_type(self):
        """Test GROUP_TYPE conversion from class to string."""
        with patch('awx.sso.utils.ldap_migrator.settings') as mock_settings:
            # Mock group type class with proper __name__ attribute
            mock_group_type = Mock()
            # Use type() to create a proper class name
            mock_group_type.__name__ = "PosixGroupType"
            type(mock_group_type).__name__ = "PosixGroupType"

            mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
            mock_settings.AUTH_LDAP_GROUP_TYPE = mock_group_type

            # Mock all other settings to None
            for key in [
                'BIND_DN',
                'BIND_PASSWORD',
                'START_TLS',
                'CONNECTION_OPTIONS',
                'USER_SEARCH',
                'USER_DN_TEMPLATE',
                'USER_ATTR_MAP',
                'GROUP_SEARCH',
                'GROUP_TYPE_PARAMS',
                'REQUIRE_GROUP',
                'DENY_GROUP',
                'USER_FLAGS_BY_GROUP',
                'ORGANIZATION_MAP',
                'TEAM_MAP',
            ]:
                setattr(mock_settings, f"AUTH_LDAP_{key}", None)

            result = self.migrator._get_ldap_instance_config("AUTH_LDAP_")

            assert result['GROUP_TYPE'] == "PosixGroupType"

    def test_build_ldap_configuration(self):
        """Test _build_ldap_configuration method."""
        settings = {
            'SERVER_URI': ['ldap://ldap.example.com'],
            'BIND_DN': 'cn=admin,dc=example,dc=com',
            'BIND_PASSWORD': 'password',
            'START_TLS': True,
            'USER_SEARCH': ['ou=users,dc=example,dc=com', 'SCOPE_SUBTREE', '(uid=%(user)s)'],
            'USER_ATTR_MAP': {'first_name': 'givenName', 'last_name': 'sn', 'email': 'mail'},
            'GROUP_SEARCH': ['ou=groups,dc=example,dc=com', 'SCOPE_SUBTREE', '(objectClass=posixGroup)'],
            'GROUP_TYPE': 'PosixGroupType',
            'GROUP_TYPE_PARAMS': {'name_attr': 'cn'},
            'USER_DN_TEMPLATE': 'uid=%(user)s,ou=users,dc=example,dc=com',
            'CONNECTION_OPTIONS': {ldap.OPT_REFERRALS: 0},
        }

        result = self.migrator._build_ldap_configuration(settings)

        assert result['SERVER_URI'] == ['ldap://ldap.example.com']
        assert result['BIND_DN'] == 'cn=admin,dc=example,dc=com'
        assert result['BIND_PASSWORD'] == 'password'
        assert result['START_TLS'] is True
        assert result['USER_SEARCH'] == ['ou=users,dc=example,dc=com', 'SCOPE_SUBTREE', '(uid=%(user)s)']
        assert result['USER_ATTR_MAP'] == {'first_name': 'givenName', 'last_name': 'sn', 'email': 'mail'}
        assert result['GROUP_SEARCH'] == ['ou=groups,dc=example,dc=com', 'SCOPE_SUBTREE', '(objectClass=posixGroup)']
        assert result['GROUP_TYPE'] == 'PosixGroupType'
        assert result['GROUP_TYPE_PARAMS'] == {'name_attr': 'cn'}
        assert result['USER_DN_TEMPLATE'] == 'uid=%(user)s,ou=users,dc=example,dc=com'
        assert 'CONNECTION_OPTIONS' in result

    def test_build_ldap_configuration_minimal(self):
        """Test _build_ldap_configuration with minimal settings."""
        settings = {'SERVER_URI': ['ldap://ldap.example.com']}

        result = self.migrator._build_ldap_configuration(settings)

        assert result == {'SERVER_URI': ['ldap://ldap.example.com']}

    def test_convert_ldap_connection_options(self):
        """Test _convert_ldap_connection_options method."""
        connection_options = {
            ldap.OPT_REFERRALS: 0,
            ldap.OPT_PROTOCOL_VERSION: 3,
            ldap.OPT_NETWORK_TIMEOUT: 30,
            ldap.OPT_X_TLS_REQUIRE_CERT: ldap.OPT_X_TLS_NEVER,
        }

        result = self.migrator._convert_ldap_connection_options(connection_options)

        assert result['OPT_REFERRALS'] == 0
        assert result['OPT_PROTOCOL_VERSION'] == 3
        assert result['OPT_NETWORK_TIMEOUT'] == 30
        assert result['OPT_X_TLS_REQUIRE_CERT'] == ldap.OPT_X_TLS_NEVER

    def test_convert_ldap_connection_options_unknown_option(self):
        """Test _convert_ldap_connection_options with unknown option."""
        connection_options = {999999: 'unknown_value', ldap.OPT_REFERRALS: 0}  # Unknown LDAP option

        result = self.migrator._convert_ldap_connection_options(connection_options)

        # Unknown option should be ignored
        assert 'OPT_REFERRALS' in result
        assert len(result) == 1

    def test_ldap_group_allow_to_gateway_format_none(self):
        """Test _ldap_group_allow_to_gateway_format with None group."""
        result = []
        output_result, next_order = self.migrator._ldap_group_allow_to_gateway_format(result, None, deny=False, start_order=1)

        assert output_result == []
        assert next_order == 1

    def test_ldap_group_allow_to_gateway_format_require_group(self):
        """Test _ldap_group_allow_to_gateway_format for require group."""
        result = []
        ldap_group = "cn=allowed_users,dc=example,dc=com"

        output_result, next_order = self.migrator._ldap_group_allow_to_gateway_format(result, ldap_group, deny=False, start_order=1)

        expected = [
            {
                "name": "LDAP-RequireGroup",
                "authenticator": -1,
                "map_type": "allow",
                "revoke": False,
                "triggers": {"groups": {"has_and": ["cn=allowed_users,dc=example,dc=com"]}},
                "order": 1,
            }
        ]

        assert output_result == expected
        assert next_order == 2

    def test_ldap_group_allow_to_gateway_format_deny_group(self):
        """Test _ldap_group_allow_to_gateway_format for deny group."""
        result = []
        ldap_group = "cn=blocked_users,dc=example,dc=com"

        output_result, next_order = self.migrator._ldap_group_allow_to_gateway_format(result, ldap_group, deny=True, start_order=5)

        expected = [
            {
                "name": "LDAP-DenyGroup",
                "authenticator": -1,
                "map_type": "allow",
                "revoke": True,
                "triggers": {"groups": {"has_or": ["cn=blocked_users,dc=example,dc=com"]}},
                "order": 5,
            }
        ]

        assert output_result == expected
        assert next_order == 6

    def test_create_gateway_authenticator(self):
        """Test create_gateway_authenticator method."""
        config = {
            'category': 'ldap',
            'settings': {'SERVER_URI': ['ldap://ldap.example.com'], 'BIND_DN': 'cn=admin,dc=example,dc=com', 'BIND_PASSWORD': 'password'},
            'org_mappers': [],
            'team_mappers': [],
            'role_mappers': [],
            'allow_mappers': [],
        }

        with patch.object(self.migrator, 'submit_authenticator') as mock_submit:
            mock_submit.return_value = {'id': 123, 'name': 'ldap'}

            result = self.migrator.create_gateway_authenticator(config)

            # Verify submit_authenticator was called
            mock_submit.assert_called_once()
            call_args = mock_submit.call_args
            gateway_config = call_args[0][0]

            assert gateway_config['name'] == 'ldap'
            assert gateway_config['type'] == 'ansible_base.authentication.authenticator_plugins.ldap'
            assert gateway_config['create_objects'] is True
            assert gateway_config['remove_users'] is False
            assert gateway_config['enabled'] is True
            assert 'configuration' in gateway_config

            assert result == {'id': 123, 'name': 'ldap'}

    def test_create_gateway_authenticator_slug_generation(self):
        """Test that create_gateway_authenticator generates correct slug."""
        config = {
            'category': 'ldap',
            'settings': {'SERVER_URI': ['ldap://ldap.example.com']},
            'org_mappers': [],
            'team_mappers': [],
            'role_mappers': [],
            'allow_mappers': [],
        }

        with patch.object(self.migrator, 'submit_authenticator') as mock_submit:
            with patch.object(self.migrator, '_generate_authenticator_slug', return_value='aap-ldap-ldap') as mock_slug:
                mock_submit.return_value = {'id': 123, 'name': 'ldap'}

                self.migrator.create_gateway_authenticator(config)

                mock_slug.assert_called_once_with('ldap', 'ldap')
                call_args = mock_submit.call_args
                gateway_config = call_args[0][0]
                assert gateway_config['slug'] == 'aap-ldap-ldap'

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_get_controller_config_with_mappings(self, mock_settings):
        """Test get_controller_config with organization and team mappings."""
        # Mock LDAP configuration with mappings
        mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
        mock_settings.AUTH_LDAP_ORGANIZATION_MAP = {"TestOrg": {"users": ["admin_group"], "admins": ["super_admin_group"]}}
        mock_settings.AUTH_LDAP_TEAM_MAP = {"TestTeam": {"organization": "TestOrg", "users": ["team_group"]}}
        mock_settings.AUTH_LDAP_USER_FLAGS_BY_GROUP = {"is_superuser": ["super_group"]}
        mock_settings.AUTH_LDAP_REQUIRE_GROUP = "cn=allowed,dc=example,dc=com"
        mock_settings.AUTH_LDAP_DENY_GROUP = "cn=blocked,dc=example,dc=com"

        # Mock all other settings to None
        for key in [
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
        ]:
            setattr(mock_settings, f"AUTH_LDAP_{key}", None)

        # Mock all other instances to return None
        for i in [1, 2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_"
            setattr(mock_settings, f"{prefix}SERVER_URI", None)
            for key in [
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
            ]:
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()

        assert len(result) == 1
        config = result[0]

        # Check that mappers were generated
        assert len(config['org_mappers']) > 0
        assert len(config['team_mappers']) > 0
        assert len(config['role_mappers']) > 0
        assert len(config['allow_mappers']) > 0  # Should have deny and require group mappers

        # Verify allow mappers contain deny and require groups
        allow_mapper_names = [mapper['name'] for mapper in config['allow_mappers']]
        assert 'LDAP-DenyGroup' in allow_mapper_names
        assert 'LDAP-RequireGroup' in allow_mapper_names

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_get_controller_config_with_specific_org_mapping(self, mock_settings):
        """Test get_controller_config with specific organization mapping including remove flags."""
        # Mock LDAP configuration with the exact mapping from the user request
        # This case is added for AAP-51531
        mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
        mock_settings.AUTH_LDAP_ORGANIZATION_MAP = {
            "Networking": {"admins": "cn=networkadmins,ou=groups,dc=example,dc=com", "users": True, "remove_admins": True, "remove_users": True}
        }
        mock_settings.AUTH_LDAP_TEAM_MAP = {}
        mock_settings.AUTH_LDAP_USER_FLAGS_BY_GROUP = {}
        mock_settings.AUTH_LDAP_REQUIRE_GROUP = None
        mock_settings.AUTH_LDAP_DENY_GROUP = None

        # Mock all other settings to None
        for key in [
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
        ]:
            setattr(mock_settings, f"AUTH_LDAP_{key}", None)

        # Mock all other instances to return None
        for i in [1, 2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_"
            setattr(mock_settings, f"{prefix}SERVER_URI", None)
            for key in [
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
            ]:
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()

        assert len(result) == 1
        config = result[0]

        # Should have 2 organization mappers: 1 for admins, 1 for users
        assert len(config['org_mappers']) == 2

        # Find the admin and user mappers
        admin_mapper = next((m for m in config['org_mappers'] if 'Admins' in m['name']), None)
        user_mapper = next((m for m in config['org_mappers'] if 'Users' in m['name']), None)

        assert admin_mapper is not None
        assert user_mapper is not None

        # Verify admin mapper details
        assert admin_mapper['organization'] == 'Networking'
        assert admin_mapper['role'] == 'Organization Admin'
        assert admin_mapper['revoke'] is True  # remove_admins: true
        assert 'Match User Groups' in admin_mapper['name']
        assert admin_mapper['triggers']['groups']['has_or'] == ['cn=networkadmins,ou=groups,dc=example,dc=com']

        # Verify user mapper details
        assert user_mapper['organization'] == 'Networking'
        assert user_mapper['role'] == 'Organization Member'
        assert user_mapper['revoke'] is True  # remove_users: true
        assert 'Always Allow' in user_mapper['name']
        assert user_mapper['triggers']['always'] == {}

        # Verify ordering (admin mapper should come before user mapper)
        admin_order = admin_mapper['order']
        user_order = user_mapper['order']
        assert admin_order < user_order

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_get_controller_config_with_complex_org_mapping(self, mock_settings):
        """Test get_controller_config with complex organization mapping scenarios."""
        # Mock LDAP configuration with various mapping types
        mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
        mock_settings.AUTH_LDAP_ORGANIZATION_MAP = {
            # This case is added for AAP-51531
            "Networking": {"admins": "cn=networkadmins,ou=groups,dc=example,dc=com", "users": True, "remove_admins": True, "remove_users": True},
            "Development": {
                "admins": ["cn=devadmins,ou=groups,dc=example,dc=com", "cn=leaddevs,ou=groups,dc=example,dc=com"],
                "users": ["cn=developers,ou=groups,dc=example,dc=com"],
                "remove_admins": False,
                "remove_users": False,
            },
            "QA": {"users": False, "remove_users": False},  # Never allow
        }
        mock_settings.AUTH_LDAP_TEAM_MAP = {}
        mock_settings.AUTH_LDAP_USER_FLAGS_BY_GROUP = {}
        mock_settings.AUTH_LDAP_REQUIRE_GROUP = None
        mock_settings.AUTH_LDAP_DENY_GROUP = None

        # Mock all other settings to None
        for key in [
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
        ]:
            setattr(mock_settings, f"AUTH_LDAP_{key}", None)

        # Mock all other instances to return None
        for i in [1, 2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_"
            setattr(mock_settings, f"{prefix}SERVER_URI", None)
            for key in [
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
            ]:
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()

        assert len(result) == 1
        config = result[0]

        # Should have 5 organization mappers total:
        # Networking: 2 (admins + users)
        # Development: 2 (admins list creates 1 + users list creates 1)
        # QA: 1 (users False creates 1)
        assert len(config['org_mappers']) == 5

        # Verify Networking mappers
        networking_mappers = [m for m in config['org_mappers'] if m['organization'] == 'Networking']
        assert len(networking_mappers) == 2

        # Verify Development mappers (should have 2: 1 admin group + 1 user group)
        development_mappers = [m for m in config['org_mappers'] if m['organization'] == 'Development']
        assert len(development_mappers) == 2

        # Verify QA mappers (should have 1: users = False creates Never Allow)
        qa_mappers = [m for m in config['org_mappers'] if m['organization'] == 'QA']
        assert len(qa_mappers) == 1
        qa_user_mapper = qa_mappers[0]
        assert 'Never Allow' in qa_user_mapper['name']
        assert qa_user_mapper['triggers']['never'] == {}
        assert qa_user_mapper['revoke'] is False

    def test_ldap_organization_mapping_with_remove_flags_integration(self):
        """Integration test for the specific organization mapping with remove flags."""
        # Test the exact scenario from the user's request using the gateway mapping functions directly
        from awx.main.utils.gateway_mapping import org_map_to_gateway_format

        # This case is added for AAP-51531
        org_map = {"Networking": {"admins": "cn=networkadmins,ou=groups,dc=example,dc=com", "users": True, "remove_admins": True, "remove_users": True}}

        result, next_order = org_map_to_gateway_format(org_map, start_order=1, auth_type='ldap')

        assert len(result) == 2

        # Find admin and user mappers
        admin_mapper = next((m for m in result if m['role'] == 'Organization Admin'), None)
        user_mapper = next((m for m in result if m['role'] == 'Organization Member'), None)

        assert admin_mapper is not None
        assert user_mapper is not None

        # Verify admin mapper
        assert admin_mapper['organization'] == 'Networking'
        assert admin_mapper['revoke'] is True
        assert admin_mapper['triggers']['groups']['has_or'] == ['cn=networkadmins,ou=groups,dc=example,dc=com']
        assert 'Match User Groups' in admin_mapper['name']

        # Verify user mapper
        assert user_mapper['organization'] == 'Networking'
        assert user_mapper['revoke'] is True
        assert user_mapper['triggers']['always'] == {}
        assert 'Always Allow' in user_mapper['name']

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_ldap_mixed_boolean_and_group_mappings(self, mock_settings):
        """Test organization mapping with mixed boolean and group assignments."""
        mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
        mock_settings.AUTH_LDAP_ORGANIZATION_MAP = {
            "MixedOrg": {
                "admins": True,  # All users are admins
                "users": ["cn=engineers,ou=groups,dc=example,dc=com", "cn=qa,ou=groups,dc=example,dc=com"],  # Specific groups are users
                "remove_admins": False,
                "remove_users": True,
            }
        }
        mock_settings.AUTH_LDAP_TEAM_MAP = {}

        # Mock all other settings to None
        for i in [None, 1, 2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_" if i is not None else "AUTH_LDAP_"
            for key in [
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
                'USER_FLAGS_BY_GROUP',
                'REQUIRE_GROUP',
                'DENY_GROUP',
            ]:
                if i is None and key in ['SERVER_URI', 'ORGANIZATION_MAP', 'TEAM_MAP']:
                    continue
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()
        assert len(result) == 1
        config = result[0]

        # Should have 2 mappers: admin (True) and users (groups)
        assert len(config['org_mappers']) == 2

        # Find admin mapper (should have 'always' trigger)
        admin_mapper = next(mapper for mapper in config['org_mappers'] if 'Admins' in mapper['name'])
        assert admin_mapper['triggers']['always'] == {}

        # Find user mapper (should have groups trigger)
        user_mapper = next(mapper for mapper in config['org_mappers'] if 'Users' in mapper['name'])
        assert user_mapper['triggers']['groups']['has_or'] == ["cn=engineers,ou=groups,dc=example,dc=com", "cn=qa,ou=groups,dc=example,dc=com"]

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_ldap_user_flags_multiple_types(self, mock_settings):
        """Test LDAP user flags with multiple flag types simultaneously."""
        mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
        mock_settings.AUTH_LDAP_ORGANIZATION_MAP = {}
        mock_settings.AUTH_LDAP_TEAM_MAP = {}
        mock_settings.AUTH_LDAP_USER_FLAGS_BY_GROUP = {
            "is_superuser": ["cn=superusers,ou=groups,dc=example,dc=com", "cn=admins,ou=groups,dc=example,dc=com"],
            "is_system_auditor": "cn=auditors,ou=groups,dc=example,dc=com",
        }

        # Mock all other settings to None
        for i in [None, 1, 2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_" if i is not None else "AUTH_LDAP_"
            for key in [
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
            ]:
                if i is None and key in ['SERVER_URI', 'ORGANIZATION_MAP', 'TEAM_MAP', 'USER_FLAGS_BY_GROUP']:
                    continue
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()
        assert len(result) == 1
        config = result[0]

        # Should have role mappers for both flag types
        assert len(config['role_mappers']) == 2

        role_mapper_names = [mapper['name'] for mapper in config['role_mappers']]
        assert "is_superuser - role" in role_mapper_names
        assert "is_system_auditor - role" in role_mapper_names

        # Verify superuser mapper has multiple groups
        superuser_mapper = next(mapper for mapper in config['role_mappers'] if mapper['name'] == "is_superuser - role")
        assert superuser_mapper['triggers']['groups']['has_or'] == ["cn=superusers,ou=groups,dc=example,dc=com", "cn=admins,ou=groups,dc=example,dc=com"]

        # Verify auditor mapper has single group
        auditor_mapper = next(mapper for mapper in config['role_mappers'] if mapper['name'] == "is_system_auditor - role")
        assert auditor_mapper['triggers']['groups']['has_or'] == ["cn=auditors,ou=groups,dc=example,dc=com"]

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_ldap_team_mapping_nonexistent_organization(self, mock_settings):
        """Test team mapping that references a non-existent organization."""
        mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
        mock_settings.AUTH_LDAP_ORGANIZATION_MAP = {}  # No organizations defined
        mock_settings.AUTH_LDAP_TEAM_MAP = {
            "OrphanTeam": {"organization": "NonExistentOrg", "users": "cn=teamusers,ou=groups,dc=example,dc=com", "remove": True}
        }

        # Mock all other settings to None
        for i in [None, 1, 2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_" if i is not None else "AUTH_LDAP_"
            for key in [
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
                'USER_FLAGS_BY_GROUP',
                'REQUIRE_GROUP',
                'DENY_GROUP',
            ]:
                if i is None and key in ['SERVER_URI', 'ORGANIZATION_MAP', 'TEAM_MAP']:
                    continue
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()
        assert len(result) == 1
        config = result[0]

        # Should still create team mapper
        assert len(config['team_mappers']) == 1
        team_mapper = config['team_mappers'][0]
        assert "OrphanTeam" in team_mapper['name']
        assert team_mapper['organization'] == "NonExistentOrg"

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_ldap_organization_with_special_characters(self, mock_settings):
        """Test organization mapping with special characters in organization names."""
        mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
        mock_settings.AUTH_LDAP_ORGANIZATION_MAP = {
            "Org-With-Dashes": {"users": True, "admins": False},
            "Org With Spaces": {"users": "cn=users,dc=example,dc=com", "admins": None},
            "Org_With_Underscores": {"users": ["cn=group1,dc=example,dc=com"], "admins": True},
        }
        mock_settings.AUTH_LDAP_TEAM_MAP = {}

        # Mock all other settings to None
        for i in [None, 1, 2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_" if i is not None else "AUTH_LDAP_"
            for key in [
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
                'USER_FLAGS_BY_GROUP',
                'REQUIRE_GROUP',
                'DENY_GROUP',
            ]:
                if i is None and key in ['SERVER_URI', 'ORGANIZATION_MAP', 'TEAM_MAP']:
                    continue
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()
        assert len(result) == 1
        config = result[0]

        # Should create mappers for all organizations with special characters
        assert len(config['org_mappers']) == 5  # 3 orgs: 2 mappers for Org-With-Dashes, 1 for Org With Spaces, 2 for Org_With_Underscores

        org_mapper_names = [mapper['name'] for mapper in config['org_mappers']]
        assert "Org-With-Dashes - Users Always Allow" in org_mapper_names
        assert "Org With Spaces - Users Match User Groups" in org_mapper_names
        assert "Org_With_Underscores - Admins Always Allow" in org_mapper_names
        assert "Org_With_Underscores - Users Match User Groups" in org_mapper_names

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_ldap_empty_organization_mapping(self, mock_settings):
        """Test LDAP config with empty organization mapping."""
        mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
        mock_settings.AUTH_LDAP_ORGANIZATION_MAP = {}  # Empty mapping
        mock_settings.AUTH_LDAP_TEAM_MAP = {}

        # Mock all other settings to None
        for i in [None, 1, 2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_" if i is not None else "AUTH_LDAP_"
            for key in [
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
                'USER_FLAGS_BY_GROUP',
                'REQUIRE_GROUP',
                'DENY_GROUP',
            ]:
                if i is None and key in ['SERVER_URI', 'ORGANIZATION_MAP', 'TEAM_MAP']:
                    continue
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()
        assert len(result) == 1
        config = result[0]

        # Should have no organization mappers
        assert len(config['org_mappers']) == 0
        assert len(config['team_mappers']) == 0

    @patch('awx.sso.utils.ldap_migrator.settings')
    def test_ldap_networking_org_mapping_aap_51531_dedicated(self, mock_settings):
        """Dedicated test for the specific LDAP organization mapping case for JIRA AAP-51531."""
        # This case is added for JIRA AAP-51531
        mock_settings.AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"
        mock_settings.AUTH_LDAP_ORGANIZATION_MAP = {
            "Networking": {"admins": "cn=networkadmins,ou=groups,dc=example,dc=com", "users": True, "remove_admins": True, "remove_users": True}
        }
        mock_settings.AUTH_LDAP_TEAM_MAP = {}
        mock_settings.AUTH_LDAP_USER_FLAGS_BY_GROUP = {}
        mock_settings.AUTH_LDAP_REQUIRE_GROUP = None
        mock_settings.AUTH_LDAP_DENY_GROUP = None

        # Mock all other settings to None
        for i in [None, 1, 2, 3, 4, 5]:
            prefix = f"AUTH_LDAP_{i}_" if i is not None else "AUTH_LDAP_"
            for key in [
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
            ]:
                if i is None and key in ['SERVER_URI', 'ORGANIZATION_MAP', 'TEAM_MAP', 'USER_FLAGS_BY_GROUP', 'REQUIRE_GROUP', 'DENY_GROUP']:
                    continue
                setattr(mock_settings, f"{prefix}{key}", None)

        result = self.migrator.get_controller_config()
        assert len(result) == 1
        config = result[0]

        # Should create exactly 2 organization mappers for the Networking org
        assert len(config['org_mappers']) == 2
        assert config['category'] == 'ldap'

        # Find admin and user mappers
        admin_mapper = next((m for m in config['org_mappers'] if 'Admins' in m['name']), None)
        user_mapper = next((m for m in config['org_mappers'] if 'Users' in m['name']), None)

        assert admin_mapper is not None
        assert user_mapper is not None

        # Verify admin mapper details for JIRA AAP-51531
        assert admin_mapper['organization'] == 'Networking'
        assert admin_mapper['revoke'] is True  # remove_admins: true
        assert 'Match User Groups' in admin_mapper['name']
        assert admin_mapper['triggers']['groups']['has_or'] == ['cn=networkadmins,ou=groups,dc=example,dc=com']

        # Verify user mapper details for JIRA AAP-51531
        assert user_mapper['organization'] == 'Networking'
        assert user_mapper['revoke'] is True  # remove_users: true
        assert 'Always Allow' in user_mapper['name']
        assert user_mapper['triggers']['always'] == {}

        # Verify both mappers have correct properties
        assert admin_mapper['map_type'] == 'organization'
        assert user_mapper['map_type'] == 'organization'
        assert admin_mapper['authenticator'] == -1
        assert user_mapper['authenticator'] == -1
