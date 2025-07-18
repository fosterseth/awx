import os
from unittest.mock import patch, Mock, call
from io import StringIO

from django.test import TestCase

from awx.main.management.commands.import_auth_config_to_gateway import Command
from awx.main.utils.gateway_client import GatewayAPIError


class TestImportAuthConfigToGatewayCommand(TestCase):
    def setUp(self):
        self.command = Command()

    def test_add_arguments(self):
        """Test that all expected arguments are properly added to the parser."""
        parser = Mock()
        self.command.add_arguments(parser)

        expected_calls = [
            call('--basic-auth', action='store_true', help='Use HTTP Basic Authentication between Controller and Gateway'),
            call('--skip-oidc', action='store_true', help='Skip importing GitHub and generic OIDC authenticators'),
            call('--skip-ldap', action='store_true', help='Skip importing LDAP authenticators'),
            call('--skip-ad', action='store_true', help='Skip importing Azure AD authenticator'),
            call('--skip-saml', action='store_true', help='Skip importing SAML authenticator'),
            call('--skip-radius', action='store_true', help='Skip importing RADIUS authenticator'),
            call('--skip-tacacs', action='store_true', help='Skip importing TACACS+ authenticator'),
            call('--skip-google', action='store_true', help='Skip importing Google OAuth2 authenticator'),
            call('--force', action='store_true', help='Force migration even if configurations already exist'),
        ]

        parser.add_argument.assert_has_calls(expected_calls, any_order=True)

    @patch.dict(os.environ, {}, clear=True)
    @patch('sys.stdout', new_callable=StringIO)
    def test_handle_missing_env_vars_basic_auth(self, mock_stdout):
        """Test that missing environment variables cause clean exit when using basic auth."""
        options = {
            'basic_auth': True,
            'skip_oidc': False,
            'skip_ldap': False,
            'skip_ad': False,
            'skip_saml': False,
            'skip_radius': False,
            'skip_tacacs': False,
            'skip_google': False,
            'force': False,
        }

        with patch('sys.exit') as mock_exit:
            with patch.object(self.command, 'stdout', mock_stdout):
                self.command.handle(**options)
                mock_exit.assert_called_once_with(0)

        output = mock_stdout.getvalue()
        self.assertIn('Missing required environment variables:', output)
        self.assertIn('GATEWAY_BASE_URL', output)
        self.assertIn('GATEWAY_USER', output)
        self.assertIn('GATEWAY_PASSWORD', output)

    @patch.dict(
        os.environ,
        {'GATEWAY_BASE_URL': 'https://gateway.example.com', 'GATEWAY_USER': 'testuser', 'GATEWAY_PASSWORD': 'testpass', 'GATEWAY_SKIP_VERIFY': 'true'},
    )
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GitHubMigrator')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.OIDCMigrator')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.SAMLMigrator')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.AzureADMigrator')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.LDAPMigrator')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.RADIUSMigrator')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.TACACSMigrator')
    @patch('sys.stdout', new_callable=StringIO)
    def test_handle_basic_auth_success(
        self, mock_stdout, mock_tacacs, mock_radius, mock_ldap, mock_azure, mock_saml, mock_oidc, mock_github, mock_gateway_client
    ):
        """Test successful execution with basic auth."""
        # Mock gateway client context manager
        mock_client_instance = Mock()
        mock_gateway_client.return_value.__enter__.return_value = mock_client_instance
        mock_gateway_client.return_value.__exit__.return_value = None

        # Mock migrators
        mock_migration_result = {
            'created': 1,
            'updated': 0,
            'unchanged': 0,
            'failed': 0,
            'mappers_created': 2,
            'mappers_updated': 0,
            'mappers_failed': 0,
        }

        for mock_migrator_class in [mock_github, mock_oidc, mock_saml, mock_azure, mock_ldap, mock_radius, mock_tacacs]:
            mock_migrator = Mock()
            mock_migrator.get_authenticator_type.return_value = 'TestAuth'
            mock_migrator.migrate.return_value = mock_migration_result
            mock_migrator_class.return_value = mock_migrator

        options = {
            'basic_auth': True,
            'skip_oidc': False,
            'skip_ldap': False,
            'skip_ad': False,
            'skip_saml': False,
            'skip_radius': False,
            'skip_tacacs': False,
            'skip_google': False,
            'force': False,
        }

        with patch.object(self.command, 'stdout', mock_stdout):
            self.command.handle(**options)

        # Verify gateway client was created with correct parameters
        mock_gateway_client.assert_called_once_with(
            base_url='https://gateway.example.com', username='testuser', password='testpass', skip_verify=True, command=self.command
        )

        # Verify all migrators were created
        mock_github.assert_called_once_with(mock_client_instance, self.command, force=False)
        mock_oidc.assert_called_once_with(mock_client_instance, self.command, force=False)
        mock_saml.assert_called_once_with(mock_client_instance, self.command, force=False)
        mock_azure.assert_called_once_with(mock_client_instance, self.command, force=False)
        mock_ldap.assert_called_once_with(mock_client_instance, self.command, force=False)
        mock_radius.assert_called_once_with(mock_client_instance, self.command, force=False)
        mock_tacacs.assert_called_once_with(mock_client_instance, self.command, force=False)

        # Verify output contains success messages
        output = mock_stdout.getvalue()
        self.assertIn('HTTP Basic Auth: true', output)
        self.assertIn('Successfully connected to Gateway', output)
        self.assertIn('Migration Summary', output)

    @patch.dict(os.environ, {'GATEWAY_SKIP_VERIFY': 'false'})
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

        options = {
            'basic_auth': False,
            'skip_oidc': True,
            'skip_ldap': True,
            'skip_ad': True,
            'skip_saml': True,
            'skip_radius': True,
            'skip_tacacs': True,
            'skip_google': True,
            'force': False,
        }

        with patch.object(self.command, 'stdout', mock_stdout):
            self.command.handle(**options)

        # Verify resource API client was created and configured
        mock_create_api_client.assert_called_once()
        self.assertTrue(mock_resource_client.verify_https)  # Should be True when GATEWAY_SKIP_VERIFY='false'
        mock_resource_client.get_service_metadata.assert_called_once()

        # Verify service token client was created
        mock_gateway_client_svc.assert_called_once_with(resource_api_client=mock_resource_client, command=self.command)

        # Verify output contains service token messages
        output = mock_stdout.getvalue()
        self.assertIn('Gateway Service Token: true', output)
        self.assertIn('No authentication configurations found to migrate.', output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_skip_flags_prevent_migrator_creation(self, mock_stdout):
        """Test that skip flags prevent corresponding migrators from being created."""
        with patch.dict(os.environ, {'GATEWAY_BASE_URL': 'https://gateway.example.com', 'GATEWAY_USER': 'testuser', 'GATEWAY_PASSWORD': 'testpass'}):
            with patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient') as mock_gateway_client:
                with patch('awx.main.management.commands.import_auth_config_to_gateway.GitHubMigrator') as mock_github:
                    with patch('awx.main.management.commands.import_auth_config_to_gateway.OIDCMigrator') as mock_oidc:
                        # Mock gateway client context manager
                        mock_client_instance = Mock()
                        mock_gateway_client.return_value.__enter__.return_value = mock_client_instance
                        mock_gateway_client.return_value.__exit__.return_value = None

                        options = {
                            'basic_auth': True,
                            'skip_oidc': True,
                            'skip_ldap': True,
                            'skip_ad': True,
                            'skip_saml': True,
                            'skip_radius': True,
                            'skip_tacacs': True,
                            'skip_google': True,
                            'force': False,
                        }

                        with patch.object(self.command, 'stdout', mock_stdout):
                            self.command.handle(**options)

                        # Verify no migrators were created
                        mock_github.assert_not_called()
                        mock_oidc.assert_not_called()

                        # Verify warning message about no configurations
                        output = mock_stdout.getvalue()
                        self.assertIn('No authentication configurations found to migrate.', output)

    @patch.dict(os.environ, {'GATEWAY_BASE_URL': 'https://gateway.example.com', 'GATEWAY_USER': 'testuser', 'GATEWAY_PASSWORD': 'testpass'})
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient')
    @patch('sys.stdout', new_callable=StringIO)
    def test_handle_gateway_api_error(self, mock_stdout, mock_gateway_client):
        """Test handling of GatewayAPIError exceptions."""
        # Mock gateway client to raise GatewayAPIError
        mock_gateway_client.side_effect = GatewayAPIError('Test error message', status_code=400, response_data={'error': 'Bad request'})

        options = {
            'basic_auth': True,
            'skip_oidc': False,
            'skip_ldap': False,
            'skip_ad': False,
            'skip_saml': False,
            'skip_radius': False,
            'skip_tacacs': False,
            'skip_google': False,
            'force': False,
        }

        with patch.object(self.command, 'stdout', mock_stdout):
            self.command.handle(**options)

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

        options = {
            'basic_auth': True,
            'skip_oidc': False,
            'skip_ldap': False,
            'skip_ad': False,
            'skip_saml': False,
            'skip_radius': False,
            'skip_tacacs': False,
            'skip_google': False,
            'force': False,
        }

        with patch.object(self.command, 'stdout', mock_stdout):
            self.command.handle(**options)

        # Verify error message output
        output = mock_stdout.getvalue()
        self.assertIn('Unexpected error during migration: Unexpected error', output)

    @patch.dict(os.environ, {'GATEWAY_BASE_URL': 'https://gateway.example.com', 'GATEWAY_USER': 'testuser', 'GATEWAY_PASSWORD': 'testpass'})
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GatewayClient')
    @patch('awx.main.management.commands.import_auth_config_to_gateway.GitHubMigrator')
    @patch('sys.stdout', new_callable=StringIO)
    def test_force_flag_passed_to_migrators(self, mock_stdout, mock_github, mock_gateway_client):
        """Test that force flag is properly passed to migrators."""
        # Mock gateway client context manager
        mock_client_instance = Mock()
        mock_gateway_client.return_value.__enter__.return_value = mock_client_instance
        mock_gateway_client.return_value.__exit__.return_value = None

        # Mock migrator
        mock_migrator = Mock()
        mock_migrator.get_authenticator_type.return_value = 'GitHub'
        mock_migrator.migrate.return_value = {
            'created': 0,
            'updated': 0,
            'unchanged': 0,
            'failed': 0,
            'mappers_created': 0,
            'mappers_updated': 0,
            'mappers_failed': 0,
        }
        mock_github.return_value = mock_migrator

        options = {
            'basic_auth': True,
            'skip_oidc': False,
            'skip_ldap': True,
            'skip_ad': True,
            'skip_saml': True,
            'skip_radius': True,
            'skip_tacacs': True,
            'skip_google': True,
            'force': True,
        }

        with patch.object(self.command, 'stdout', mock_stdout):
            self.command.handle(**options)

        # Verify migrator was created with force=True
        mock_github.assert_called_once_with(mock_client_instance, self.command, force=True)

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
        mock_github_migrator = Mock()
        mock_github_migrator.get_authenticator_type.return_value = 'GitHub'
        mock_github_migrator.migrate.return_value = {
            'created': 1,
            'updated': 0,
            'unchanged': 0,
            'failed': 0,
            'mappers_created': 2,
            'mappers_updated': 0,
            'mappers_failed': 0,
        }
        mock_github.return_value = mock_github_migrator

        mock_oidc_migrator = Mock()
        mock_oidc_migrator.get_authenticator_type.return_value = 'OIDC'
        mock_oidc_migrator.migrate.return_value = {
            'created': 0,
            'updated': 1,
            'unchanged': 1,
            'failed': 0,
            'mappers_created': 1,
            'mappers_updated': 1,
            'mappers_failed': 0,
        }
        mock_oidc.return_value = mock_oidc_migrator

        options = {
            'basic_auth': True,
            'skip_oidc': False,
            'skip_ldap': True,
            'skip_ad': True,
            'skip_saml': True,
            'skip_radius': True,
            'skip_tacacs': True,
            'skip_google': True,
            'force': False,
        }

        with patch.object(self.command, 'stdout', mock_stdout):
            self.command.handle(**options)

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

                    options = {
                        'basic_auth': True,
                        'skip_oidc': True,
                        'skip_ldap': True,
                        'skip_ad': True,
                        'skip_saml': True,
                        'skip_radius': True,
                        'skip_tacacs': True,
                        'skip_google': True,
                        'force': False,
                    }

                    with patch.object(self.command, 'stdout', mock_stdout):
                        self.command.handle(**options)

                    # Verify gateway client was called with correct skip_verify value
                    mock_gateway_client.assert_called_once_with(
                        base_url='https://gateway.example.com', username='testuser', password='testpass', skip_verify=expected, command=self.command
                    )

                    # Reset for next iteration
                    mock_gateway_client.reset_mock()
                    mock_stdout.seek(0)
                    mock_stdout.truncate(0)
