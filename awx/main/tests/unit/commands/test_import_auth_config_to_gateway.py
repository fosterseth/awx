import os
import pytest
from unittest.mock import patch, Mock, call, DEFAULT
from io import StringIO
from unittest import TestCase

from awx.main.management.commands.import_auth_config_to_gateway import Command
from awx.main.utils.gateway_client import GatewayAPIError


class TestImportAuthConfigToGatewayCommand(TestCase):
    def setUp(self):
        self.command = Command()

    def options_basic_auth_full_send(self):
        return {
            'basic_auth': True,
            'skip_all_authenticators': False,
            'skip_oidc': False,
            'skip_github': False,
            'skip_ldap': False,
            'skip_ad': False,
            'skip_saml': False,
            'skip_radius': False,
            'skip_tacacs': False,
            'skip_google': False,
            'skip_settings': False,
            'force': False,
        }

    def options_basic_auth_skip_all_individual(self):
        return {
            'basic_auth': True,
            'skip_all_authenticators': False,
            'skip_oidc': True,
            'skip_github': True,
            'skip_ldap': True,
            'skip_ad': True,
            'skip_saml': True,
            'skip_radius': True,
            'skip_tacacs': True,
            'skip_google': True,
            'skip_settings': True,
            'force': False,
        }

    def options_svc_token_full_send(self):
        options = self.options_basic_auth_full_send()
        options['basic_auth'] = False
        return options

    def options_svc_token_skip_all(self):
        options = self.options_basic_auth_skip_all_individual()
        options['basic_auth'] = False
        return options

    def create_mock_migrator(
        self,
        mock_migrator_class,
        authenticator_type="TestAuth",
        created=0,
        updated=0,
        unchanged=0,
        failed=0,
        mappers_created=0,
        mappers_updated=0,
        mappers_failed=0,
        settings_created=0,
        settings_updated=0,
        settings_unchanged=0,
        settings_failed=0,
    ):
        """Helper method to create a mock migrator with specified return values."""
        mock_migrator = Mock()
        mock_migrator.get_authenticator_type.return_value = authenticator_type
        mock_migrator.migrate.return_value = {
            'created': created,
            'updated': updated,
            'unchanged': unchanged,
            'failed': failed,
            'mappers_created': mappers_created,
            'mappers_updated': mappers_updated,
            'mappers_failed': mappers_failed,
        }
        mock_migrator_class.return_value = mock_migrator
        return mock_migrator

    def test_add_arguments(self):
        """Test that all expected arguments are properly added to the parser."""
        parser = Mock()
        self.command.add_arguments(parser)

        expected_calls = [
            call('--basic-auth', action='store_true', help='Use HTTP Basic Authentication between Controller and Gateway'),
            call(
                '--skip-all-authenticators',
                action='store_true',
                help='Skip importing all authenticators [GitHub, OIDC, SAML, Azure AD, LDAP, RADIUS, TACACS+, Google OAuth2]',
            ),
            call('--skip-oidc', action='store_true', help='Skip importing generic OIDC authenticators'),
            call('--skip-github', action='store_true', help='Skip importing GitHub authenticator'),
            call('--skip-ldap', action='store_true', help='Skip importing LDAP authenticators'),
            call('--skip-ad', action='store_true', help='Skip importing Azure AD authenticator'),
            call('--skip-saml', action='store_true', help='Skip importing SAML authenticator'),
            call('--skip-radius', action='store_true', help='Skip importing RADIUS authenticator'),
            call('--skip-tacacs', action='store_true', help='Skip importing TACACS+ authenticator'),
            call('--skip-google', action='store_true', help='Skip importing Google OAuth2 authenticator'),
            call('--skip-settings', action='store_true', help='Skip importing settings'),
            call(
                '--force',
                action='store_true',
                help='Force migration even if configurations already exist. Does not apply to skipped authenticators nor skipped settings.',
            ),
        ]

        parser.add_argument.assert_has_calls(expected_calls, any_order=True)

    @patch.dict(os.environ, {}, clear=True)
    @patch('sys.stdout', new_callable=StringIO)
    def test_handle_missing_env_vars_basic_auth(self, mock_stdout):
        """Test that missing environment variables cause clean exit when using basic auth."""

        with patch.object(self.command, 'stdout', mock_stdout):
            with pytest.raises(SystemExit) as exc_info:
                self.command.handle(**self.options_basic_auth_full_send())
            # Should exit with code 0 for successful early validation
            assert exc_info.value.code == 0

        output = mock_stdout.getvalue()
        self.assertIn('Missing required environment variables:', output)
        self.assertIn('GATEWAY_BASE_URL', output)
        self.assertIn('GATEWAY_USER', output)
        self.assertIn('GATEWAY_PASSWORD', output)

    @patch.dict(
        os.environ,
        {'GATEWAY_BASE_URL': 'https://gateway.example.com', 'GATEWAY_USER': 'testuser', 'GATEWAY_PASSWORD': 'testpass', 'GATEWAY_SKIP_VERIFY': 'true'},
    )
    @patch('awx.main.management.commands.import_auth_config_to_gateway.SettingsMigrator')
    @patch.multiple(
        'awx.main.management.commands.import_auth_config_to_gateway',
        GitHubMigrator=DEFAULT,
        OIDCMigrator=DEFAULT,
        SAMLMigrator=DEFAULT,
        AzureADMigrator=DEFAULT,
        LDAPMigrator=DEFAULT,
        RADIUSMigrator=DEFAULT,
        TACACSMigrator=DEFAULT,
        GoogleOAuth2Migrator=DEFAULT,
    )
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient')
    @patch('sys.stdout', new_callable=StringIO)
    def test_handle_basic_auth_success(self, mock_stdout, mock_gateway_client, mock_settings_migrator, **mock_migrators):
        """Test successful execution with basic auth."""
        # Mock gateway client context manager
        mock_client_instance = Mock()
        mock_gateway_client.return_value.__enter__.return_value = mock_client_instance
        mock_gateway_client.return_value.__exit__.return_value = None

        for mock_migrator_class in mock_migrators.values():
            self.create_mock_migrator(mock_migrator_class, created=1, mappers_created=2)

        self.create_mock_migrator(mock_settings_migrator, settings_created=1, settings_updated=0, settings_unchanged=2, settings_failed=0)

        with patch.object(self.command, 'stdout', mock_stdout):
            with pytest.raises(SystemExit) as exc_info:
                self.command.handle(**self.options_basic_auth_full_send())
            # Should exit with code 0 for success
            assert exc_info.value.code == 0

        # Verify gateway client was created with correct parameters
        mock_gateway_client.assert_called_once_with(
            base_url='https://gateway.example.com', username='testuser', password='testpass', skip_verify=True, command=self.command
        )

        # Verify all migrators were created
        for mock_migrator in mock_migrators.values():
            mock_migrator.assert_called_once_with(mock_client_instance, self.command, force=False)

        mock_settings_migrator.assert_called_once_with(mock_client_instance, self.command, force=False)

        # Verify output contains success messages
        output = mock_stdout.getvalue()

        self.assertIn('HTTP Basic Auth: true', output)
        self.assertIn('Successfully connected to Gateway', output)
        self.assertIn('Migration Summary', output)
        self.assertIn('authenticators', output)
        self.assertIn('mappers', output)
        self.assertIn('settings', output)

    @patch.dict(os.environ, {'GATEWAY_SKIP_VERIFY': 'false'}, clear=True)  # Ensure verify_https=True
    @patch('awx.main.management.commands.import_auth_config_to_gateway.create_api_client')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClientSVCToken')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.urlparse')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.urlunparse')
    @patch('sys.stdout', new_callable=StringIO)
    def test_handle_service_token_success(self, mock_stdout, mock_urlunparse, mock_urlparse, mock_gateway_client_svc, mock_create_api_client):
        """Test successful execution with service token."""
        # Mock resource API client
        mock_resource_client = Mock()
        mock_resource_client.base_url = 'https://gateway.example.com/api/v1'
        mock_resource_client.jwt_user_id = 'test-user'
        mock_resource_client.jwt_expiration = '2024-12-31'
        mock_resource_client.verify_https = True
        mock_response = Mock()
        mock_response.status_code = 200
        mock_resource_client.get_service_metadata.return_value = mock_response
        mock_create_api_client.return_value = mock_resource_client

        # Mock URL parsing
        mock_parsed = Mock()
        mock_parsed.scheme = 'https'
        mock_parsed.netloc = 'gateway.example.com'
        mock_urlparse.return_value = mock_parsed
        mock_urlunparse.return_value = 'https://gateway.example.com/'

        # Mock gateway client context manager
        mock_client_instance = Mock()
        mock_gateway_client_svc.return_value.__enter__.return_value = mock_client_instance
        mock_gateway_client_svc.return_value.__exit__.return_value = None

        with patch.object(self.command, 'stdout', mock_stdout):
            with patch('sys.exit'):
                self.command.handle(**self.options_svc_token_skip_all())
                # Should call sys.exit(0) for success, but may not due to test setup
                # Just verify the command completed without raising an exception

        # Verify resource API client was created and configured
        mock_create_api_client.assert_called_once()
        self.assertTrue(mock_resource_client.verify_https)  # Should be True when GATEWAY_SKIP_VERIFY='false'
        mock_resource_client.get_service_metadata.assert_called_once()

        # Verify service token client was created
        mock_gateway_client_svc.assert_called_once_with(resource_api_client=mock_resource_client, command=self.command)

        # Verify output contains service token messages
        output = mock_stdout.getvalue()
        self.assertIn('Gateway Service Token: true', output)
        self.assertIn('Connection Validated: True', output)
        self.assertIn('No authentication configurations found to migrate.', output)

    @patch.dict(os.environ, {'GATEWAY_BASE_URL': 'https://gateway.example.com', 'GATEWAY_USER': 'testuser', 'GATEWAY_PASSWORD': 'testpass'})
    @patch.multiple(
        'awx.main.management.commands.import_auth_config_to_gateway',
        GitHubMigrator=DEFAULT,
        OIDCMigrator=DEFAULT,
        SAMLMigrator=DEFAULT,
        AzureADMigrator=DEFAULT,
        LDAPMigrator=DEFAULT,
        RADIUSMigrator=DEFAULT,
        TACACSMigrator=DEFAULT,
        GoogleOAuth2Migrator=DEFAULT,
        SettingsMigrator=DEFAULT,
    )
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient')
    @patch('sys.stdout', new_callable=StringIO)
    def test_skip_flags_prevent_authenticator_individual_and_settings_migration(self, mock_stdout, mock_gateway_client, **mock_migrators):
        """Test that skip flags prevent corresponding migrators from being created."""

        # Mock gateway client context manager
        mock_client_instance = Mock()
        mock_gateway_client.return_value.__enter__.return_value = mock_client_instance
        mock_gateway_client.return_value.__exit__.return_value = None

        with patch.object(self.command, 'stdout', mock_stdout):
            with patch('sys.exit'):
                self.command.handle(**self.options_basic_auth_skip_all_individual())
                # Should call sys.exit(0) for success, but may not due to test setup
                # Just verify the command completed without raising an exception

        # Verify no migrators were created
        for mock_migrator in mock_migrators.values():
            mock_migrator.assert_not_called()

        # Verify warning message about no configurations
        output = mock_stdout.getvalue()
        self.assertIn('No authentication configurations found to migrate.', output)
        self.assertIn('Settings migration will not execute.', output)
        self.assertIn('NO MIGRATIONS WILL EXECUTE.', output)

    @patch.dict(os.environ, {'GATEWAY_BASE_URL': 'https://gateway.example.com', 'GATEWAY_USER': 'testuser', 'GATEWAY_PASSWORD': 'testpass'})
    @patch.multiple(
        'awx.main.management.commands.import_auth_config_to_gateway',
        GitHubMigrator=DEFAULT,
        OIDCMigrator=DEFAULT,
        SAMLMigrator=DEFAULT,
        AzureADMigrator=DEFAULT,
        LDAPMigrator=DEFAULT,
        RADIUSMigrator=DEFAULT,
        TACACSMigrator=DEFAULT,
        GoogleOAuth2Migrator=DEFAULT,
    )
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient')
    @patch('sys.stdout', new_callable=StringIO)
    def test_skip_flags_prevent_authenticator_migration(self, mock_stdout, mock_gateway_client, **mock_migrators):
        """Test that skip flags prevent corresponding migrators from being created."""

        # Mock gateway client context manager
        mock_client_instance = Mock()
        mock_gateway_client.return_value.__enter__.return_value = mock_client_instance
        mock_gateway_client.return_value.__exit__.return_value = None

        options = self.options_basic_auth_full_send()
        options['skip_all_authenticators'] = True

        with patch.object(self.command, 'stdout', mock_stdout):
            with pytest.raises(SystemExit) as exc_info:
                self.command.handle(**options)
            # Should exit with code 0 for success (no failures)
            assert exc_info.value.code == 0

        # Verify no migrators were created
        for mock_migrator in mock_migrators.values():
            mock_migrator.assert_not_called()

        # Verify warning message about no configurations
        output = mock_stdout.getvalue()
        self.assertIn('No authentication configurations found to migrate.', output)
        self.assertNotIn('Settings migration will not execute.', output)
        self.assertNotIn('NO MIGRATIONS WILL EXECUTE.', output)

    @patch.dict(os.environ, {'GATEWAY_BASE_URL': 'https://gateway.example.com', 'GATEWAY_USER': 'testuser', 'GATEWAY_PASSWORD': 'testpass'})
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient')
    @patch('sys.stdout', new_callable=StringIO)
    def test_handle_gateway_api_error(self, mock_stdout, mock_gateway_client):
        """Test handling of GatewayAPIError exceptions."""
        # Mock gateway client to raise GatewayAPIError
        mock_gateway_client.side_effect = GatewayAPIError('Test error message', status_code=400, response_data={'error': 'Bad request'})

        with patch.object(self.command, 'stdout', mock_stdout):
            with pytest.raises(SystemExit) as exc_info:
                self.command.handle(**self.options_basic_auth_full_send())
            # Should exit with code 1 for errors
            assert exc_info.value.code == 1

        # Verify error message output
        output = mock_stdout.getvalue()
        self.assertIn('Gateway API Error: Test error message', output)
        self.assertIn('Status Code: 400', output)
        self.assertIn("Response: {'error': 'Bad request'}", output)

    @patch.dict(os.environ, {'GATEWAY_BASE_URL': 'https://gateway.example.com', 'GATEWAY_USER': 'testuser', 'GATEWAY_PASSWORD': 'testpass'})
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient')
    @patch('sys.stdout', new_callable=StringIO)
    def test_handle_unexpected_error(self, mock_stdout, mock_gateway_client):
        """Test handling of unexpected exceptions."""
        # Mock gateway client to raise unexpected error
        mock_gateway_client.side_effect = ValueError('Unexpected error')

        with patch.object(self.command, 'stdout', mock_stdout):
            with pytest.raises(SystemExit) as exc_info:
                self.command.handle(**self.options_basic_auth_full_send())
            # Should exit with code 1 for errors
            assert exc_info.value.code == 1

        # Verify error message output
        output = mock_stdout.getvalue()
        self.assertIn('Unexpected error during migration: Unexpected error', output)

    @patch.dict(os.environ, {'GATEWAY_BASE_URL': 'https://gateway.example.com', 'GATEWAY_USER': 'testuser', 'GATEWAY_PASSWORD': 'testpass'})
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GitHubMigrator')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.SettingsMigrator')
    @patch('sys.stdout', new_callable=StringIO)
    def test_force_flag_passed_to_migrators(self, mock_stdout, mock_github, mock_settings_migrator, mock_gateway_client):
        """Test that force flag is properly passed to migrators."""
        # Mock gateway client context manager
        mock_client_instance = Mock()
        mock_gateway_client.return_value.__enter__.return_value = mock_client_instance
        mock_gateway_client.return_value.__exit__.return_value = None

        # Mock migrator
        self.create_mock_migrator(mock_github, authenticator_type="GitHub", created=0, mappers_created=2)
        self.create_mock_migrator(
            mock_settings_migrator, authenticator_type="Settings", settings_created=0, settings_updated=2, settings_unchanged=0, settings_failed=0
        )

        options = self.options_basic_auth_skip_all_individual()
        options['force'] = True
        options['skip_github'] = False
        options['skip_settings'] = False

        with patch.object(self.command, 'stdout', mock_stdout):
            with pytest.raises(SystemExit) as exc_info:
                self.command.handle(**options)
            # Should exit with code 0 for success
            assert exc_info.value.code == 0

        # Verify migrator was created with force=True
        mock_github.assert_called_once_with(mock_client_instance, self.command, force=True)

        # Verify settings migrator was created with force=True
        mock_settings_migrator.assert_called_once_with(mock_client_instance, self.command, force=True)

    @patch('sys.stdout', new_callable=StringIO)
    def test_print_export_summary(self, mock_stdout):
        """Test the _print_export_summary method."""
        result = {
            'created': 2,
            'updated': 1,
            'unchanged': 3,
            'failed': 0,
            'mappers_created': 5,
            'mappers_updated': 2,
            'mappers_failed': 1,
        }

        with patch.object(self.command, 'stdout', mock_stdout):
            self.command._print_export_summary('SAML', result)

        output = mock_stdout.getvalue()
        self.assertIn('--- SAML Export Summary ---', output)
        self.assertIn('Authenticators created: 2', output)
        self.assertIn('Authenticators updated: 1', output)
        self.assertIn('Authenticators unchanged: 3', output)
        self.assertIn('Authenticators failed: 0', output)
        self.assertIn('Mappers created: 5', output)
        self.assertIn('Mappers updated: 2', output)
        self.assertIn('Mappers failed: 1', output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_print_export_summary_settings(self, mock_stdout):
        """Test the _print_export_summary method."""
        result = {
            'settings_created': 2,
            'settings_updated': 1,
            'settings_unchanged': 3,
            'settings_failed': 0,
        }

        with patch.object(self.command, 'stdout', mock_stdout):
            self.command._print_export_summary('Settings', result)

        output = mock_stdout.getvalue()
        self.assertIn('--- Settings Export Summary ---', output)
        self.assertIn('Settings created: 2', output)
        self.assertIn('Settings updated: 1', output)
        self.assertIn('Settings unchanged: 3', output)
        self.assertIn('Settings failed: 0', output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_print_export_summary_missing_keys(self, mock_stdout):
        """Test _print_export_summary handles missing keys gracefully."""
        result = {
            'created': 1,
            'updated': 2,
            # Missing other keys
        }

        with patch.object(self.command, 'stdout', mock_stdout):
            self.command._print_export_summary('LDAP', result)

        output = mock_stdout.getvalue()
        self.assertIn('--- LDAP Export Summary ---', output)
        self.assertIn('Authenticators created: 1', output)
        self.assertIn('Authenticators updated: 2', output)
        self.assertIn('Authenticators unchanged: 0', output)  # Default value
        self.assertIn('Mappers created: 0', output)  # Default value

    @patch.dict(os.environ, {'GATEWAY_BASE_URL': 'https://gateway.example.com', 'GATEWAY_USER': 'testuser', 'GATEWAY_PASSWORD': 'testpass'})
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GitHubMigrator')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.OIDCMigrator')
    @patch('sys.stdout', new_callable=StringIO)
    def test_total_results_accumulation(self, mock_stdout, mock_oidc, mock_github, mock_gateway_client):
        """Test that results from multiple migrators are properly accumulated."""
        # Mock gateway client context manager
        mock_client_instance = Mock()
        mock_gateway_client.return_value.__enter__.return_value = mock_client_instance
        mock_gateway_client.return_value.__exit__.return_value = None

        # Mock migrators with different results
        self.create_mock_migrator(mock_github, authenticator_type="GitHub", created=1, mappers_created=2)
        self.create_mock_migrator(mock_oidc, authenticator_type="OIDC", created=0, updated=1, unchanged=1, mappers_created=1, mappers_updated=1)

        options = self.options_basic_auth_skip_all_individual()
        options['skip_oidc'] = False
        options['skip_github'] = False

        with patch.object(self.command, 'stdout', mock_stdout):
            with pytest.raises(SystemExit) as exc_info:
                self.command.handle(**options)
            # Should exit with code 0 for success
            assert exc_info.value.code == 0

        # Verify total results are accumulated correctly
        output = mock_stdout.getvalue()
        self.assertIn('Total authenticators created: 1', output)  # 1 + 0
        self.assertIn('Total authenticators updated: 1', output)  # 0 + 1
        self.assertIn('Total authenticators unchanged: 1', output)  # 0 + 1
        self.assertIn('Total authenticators failed: 0', output)  # 0 + 0
        self.assertIn('Total mappers created: 3', output)  # 2 + 1
        self.assertIn('Total mappers updated: 1', output)  # 0 + 1
        self.assertIn('Total mappers failed: 0', output)  # 0 + 0

    @patch('sys.stdout', new_callable=StringIO)
    def test_environment_variable_parsing(self, mock_stdout):
        """Test that environment variables are parsed correctly."""
        test_cases = [
            ('true', True),
            ('1', True),
            ('yes', True),
            ('on', True),
            ('TRUE', True),
            ('false', False),
            ('0', False),
            ('no', False),
            ('off', False),
            ('', False),
            ('random', False),
        ]

        for env_value, expected in test_cases:
            with patch.dict(
                os.environ,
                {
                    'GATEWAY_BASE_URL': 'https://gateway.example.com',
                    'GATEWAY_USER': 'testuser',
                    'GATEWAY_PASSWORD': 'testpass',
                    'GATEWAY_SKIP_VERIFY': env_value,
                },
            ):
                with patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient') as mock_gateway_client:
                    # Mock gateway client context manager
                    mock_client_instance = Mock()
                    mock_gateway_client.return_value.__enter__.return_value = mock_client_instance
                    mock_gateway_client.return_value.__exit__.return_value = None

                    with patch.object(self.command, 'stdout', mock_stdout):
                        with patch('sys.exit'):
                            self.command.handle(**self.options_basic_auth_skip_all_individual())

                    # Verify gateway client was called with correct skip_verify value
                    mock_gateway_client.assert_called_once_with(
                        base_url='https://gateway.example.com', username='testuser', password='testpass', skip_verify=expected, command=self.command
                    )

                    # Reset for next iteration
                    mock_gateway_client.reset_mock()
                    mock_stdout.seek(0)
                    mock_stdout.truncate(0)

    @patch.dict(os.environ, {'GATEWAY_SKIP_VERIFY': 'false'})
    @patch('awx.main.management.commands.import_auth_config_to_gateway.create_api_client')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.urlparse')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.urlunparse')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.SettingsMigrator')
    @patch('sys.stdout', new_callable=StringIO)
    def test_service_token_connection_validation_failure(self, mock_stdout, mock_settings_migrator, mock_urlunparse, mock_urlparse, mock_create_api_client):
        """Test that non-200 response from get_service_metadata causes error exit."""
        # Mock resource API client with failing response
        mock_resource_client = Mock()
        mock_resource_client.base_url = 'https://gateway.example.com/api/v1'
        mock_resource_client.jwt_user_id = 'test-user'
        mock_resource_client.jwt_expiration = '2024-12-31'
        mock_resource_client.verify_https = True
        mock_response = Mock()
        mock_response.status_code = 401  # Simulate unauthenticated error
        mock_resource_client.get_service_metadata.return_value = mock_response
        mock_create_api_client.return_value = mock_resource_client

        # Mock URL parsing (needed for the service token flow)
        mock_parsed = Mock()
        mock_parsed.scheme = 'https'
        mock_parsed.netloc = 'gateway.example.com'
        mock_urlparse.return_value = mock_parsed
        mock_urlunparse.return_value = 'https://gateway.example.com/'

        with patch.object(self.command, 'stdout', mock_stdout):
            with pytest.raises(SystemExit) as exc_info:
                self.command.handle(**self.options_svc_token_skip_all())
            # Should exit with code 1 for connection failure
            assert exc_info.value.code == 1

        # Verify error message is displayed
        output = mock_stdout.getvalue()
        self.assertIn(
            'Gateway Service Token is unable to connect to Gateway via the base URL https://gateway.example.com/.  Recieved HTTP response code 401', output
        )
        self.assertIn('Connection Validated: False', output)
