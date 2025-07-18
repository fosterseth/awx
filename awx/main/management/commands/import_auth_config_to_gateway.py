import sys
import os

from django.core.management.base import BaseCommand
from urllib.parse import urlparse, urlunparse
from awx.sso.utils.azure_ad_migrator import AzureADMigrator
from awx.sso.utils.github_migrator import GitHubMigrator
from awx.sso.utils.ldap_migrator import LDAPMigrator
from awx.sso.utils.oidc_migrator import OIDCMigrator
from awx.sso.utils.saml_migrator import SAMLMigrator
from awx.sso.utils.radius_migrator import RADIUSMigrator
from awx.sso.utils.tacacs_migrator import TACACSMigrator
from awx.sso.utils.google_oauth2_migrator import GoogleOAuth2Migrator
from awx.main.utils.gateway_client import GatewayClient, GatewayAPIError
from awx.main.utils.gateway_client_svc_token import GatewayClientSVCToken
from ansible_base.resource_registry.tasks.sync import create_api_client


class Command(BaseCommand):
    help = 'Import existing auth provider configurations to AAP Gateway via API requests'

    def add_arguments(self, parser):
        parser.add_argument('--basic-auth', action='store_true', help='Use HTTP Basic Authentication between Controller and Gateway')
        parser.add_argument('--skip-oidc', action='store_true', help='Skip importing GitHub and generic OIDC authenticators')
        parser.add_argument('--skip-ldap', action='store_true', help='Skip importing LDAP authenticators')
        parser.add_argument('--skip-ad', action='store_true', help='Skip importing Azure AD authenticator')
        parser.add_argument('--skip-saml', action='store_true', help='Skip importing SAML authenticator')
        parser.add_argument('--skip-radius', action='store_true', help='Skip importing RADIUS authenticator')
        parser.add_argument('--skip-tacacs', action='store_true', help='Skip importing TACACS+ authenticator')
        parser.add_argument('--skip-google', action='store_true', help='Skip importing Google OAuth2 authenticator')
        parser.add_argument('--force', action='store_true', help='Force migration even if configurations already exist')

    def handle(self, *args, **options):
        # Read Gateway connection parameters from environment variables
        gateway_base_url = os.getenv('GATEWAY_BASE_URL')
        gateway_user = os.getenv('GATEWAY_USER')
        gateway_password = os.getenv('GATEWAY_PASSWORD')
        gateway_skip_verify = os.getenv('GATEWAY_SKIP_VERIFY', '').lower() in ('true', '1', 'yes', 'on')

        skip_oidc = options['skip_oidc']
        skip_ldap = options['skip_ldap']
        skip_ad = options['skip_ad']
        skip_saml = options['skip_saml']
        skip_radius = options['skip_radius']
        skip_tacacs = options['skip_tacacs']
        skip_google = options['skip_google']
        force = options['force']
        basic_auth = options['basic_auth']

        management_command_validation_errors = []

        # If the management command isn't called with all parameters needed to talk to Gateway, consider
        # it a dry-run and exit cleanly
        if not gateway_base_url and basic_auth:
            management_command_validation_errors.append('- GATEWAY_BASE_URL: Base URL of the AAP Gateway instance')
        if (not gateway_user or not gateway_password) and basic_auth:
            management_command_validation_errors.append('- GATEWAY_USER: Username for AAP Gateway authentication')
            management_command_validation_errors.append('- GATEWAY_PASSWORD: Password for AAP Gateway authentication')

        if len(management_command_validation_errors) > 0:
            self.stdout.write(self.style.WARNING('Missing required environment variables:'))
            for validation_error in management_command_validation_errors:
                self.stdout.write(self.style.WARNING(f"{validation_error}"))
            self.stdout.write(self.style.WARNING('- GATEWAY_SKIP_VERIFY: Skip SSL certificate verification (optional)'))
            sys.exit(0)

        resource_api_client = None
        response = None

        if basic_auth:
            self.stdout.write(self.style.SUCCESS('HTTP Basic Auth: true'))
            self.stdout.write(self.style.SUCCESS(f'Gateway Base URL: {gateway_base_url}'))
            self.stdout.write(self.style.SUCCESS(f'Gateway User: {gateway_user}'))
            self.stdout.write(self.style.SUCCESS('Gateway Password: *******************'))
            self.stdout.write(self.style.SUCCESS(f'Skip SSL Verification: {gateway_skip_verify}'))

        else:
            resource_api_client = create_api_client()
            resource_api_client.verify_https = not gateway_skip_verify
            response = resource_api_client.get_service_metadata()
            parsed_url = urlparse(resource_api_client.base_url)
            resource_api_client.base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, '/', '', '', ''))

            self.stdout.write(self.style.SUCCESS('Gateway Service Token: true'))
            self.stdout.write(self.style.SUCCESS(f'Gateway Base URL: {resource_api_client.base_url}'))
            self.stdout.write(self.style.SUCCESS(f'Gateway JWT User: {resource_api_client.jwt_user_id}'))
            self.stdout.write(self.style.SUCCESS(f'Gateway JWT Expiration: {resource_api_client.jwt_expiration}'))
            self.stdout.write(self.style.SUCCESS(f'Skip SSL Verification: {not resource_api_client.verify_https}'))
            self.stdout.write(self.style.SUCCESS(f'Connection Validated: {response.status_code == 200}'))

        # Create Gateway client and run migrations
        try:
            self.stdout.write(self.style.SUCCESS('\n=== Connecting to Gateway ==='))
            pre_gateway_client = None
            if basic_auth:
                self.stdout.write(self.style.SUCCESS('\n=== With Basic HTTP Auth ==='))
                pre_gateway_client = GatewayClient(
                    base_url=gateway_base_url, username=gateway_user, password=gateway_password, skip_verify=gateway_skip_verify, command=self
                )

            else:
                self.stdout.write(self.style.SUCCESS('\n=== With Service Token ==='))
                pre_gateway_client = GatewayClientSVCToken(resource_api_client=resource_api_client, command=self)

            with pre_gateway_client as gateway_client:
                self.stdout.write(self.style.SUCCESS('Successfully connected to Gateway'))

                # Initialize migrators
                migrators = []
                if not skip_oidc:
                    migrators.append(GitHubMigrator(gateway_client, self, force=force))
                    migrators.append(OIDCMigrator(gateway_client, self, force=force))

                if not skip_saml:
                    migrators.append(SAMLMigrator(gateway_client, self, force=force))

                if not skip_ad:
                    migrators.append(AzureADMigrator(gateway_client, self, force=force))

                if not skip_ldap:
                    migrators.append(LDAPMigrator(gateway_client, self, force=force))

                if not skip_radius:
                    migrators.append(RADIUSMigrator(gateway_client, self, force=force))

                if not skip_tacacs:
                    migrators.append(TACACSMigrator(gateway_client, self, force=force))

                if not skip_google:
                    migrators.append(GoogleOAuth2Migrator(gateway_client, self, force=force))

                # Run migrations
                total_results = {
                    'created': 0,
                    'updated': 0,
                    'unchanged': 0,
                    'failed': 0,
                    'mappers_created': 0,
                    'mappers_updated': 0,
                    'mappers_failed': 0,
                }

                if not migrators:
                    self.stdout.write(self.style.WARNING('No authentication configurations found to migrate.'))
                else:
                    for migrator in migrators:
                        self.stdout.write(self.style.SUCCESS(f'\n=== Migrating {migrator.get_authenticator_type()} Configurations ==='))
                        result = migrator.migrate()
                        self._print_export_summary(migrator.get_authenticator_type(), result)

                        # Accumulate results - handle missing keys gracefully
                        for key in total_results:
                            total_results[key] += result.get(key, 0)

                    # Overall summary
                    self.stdout.write(self.style.SUCCESS('\n=== Migration Summary ==='))
                    self.stdout.write(f'Total authenticators created: {total_results["created"]}')
                    self.stdout.write(f'Total authenticators updated: {total_results["updated"]}')
                    self.stdout.write(f'Total authenticators unchanged: {total_results["unchanged"]}')
                    self.stdout.write(f'Total authenticators failed: {total_results["failed"]}')
                    self.stdout.write(f'Total mappers created: {total_results["mappers_created"]}')
                    self.stdout.write(f'Total mappers updated: {total_results["mappers_updated"]}')
                    self.stdout.write(f'Total mappers failed: {total_results["mappers_failed"]}')

        except GatewayAPIError as e:
            self.stdout.write(self.style.ERROR(f'Gateway API Error: {e.message}'))
            if e.status_code:
                self.stdout.write(self.style.ERROR(f'Status Code: {e.status_code}'))
            if e.response_data:
                self.stdout.write(self.style.ERROR(f'Response: {e.response_data}'))
            return
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Unexpected error during migration: {str(e)}'))
            return

    def _print_export_summary(self, config_type, result):
        """Print a summary of the export results."""
        self.stdout.write(f'\n--- {config_type} Export Summary ---')
        self.stdout.write(f'Authenticators created: {result.get("created", 0)}')
        self.stdout.write(f'Authenticators updated: {result.get("updated", 0)}')
        self.stdout.write(f'Authenticators unchanged: {result.get("unchanged", 0)}')
        self.stdout.write(f'Authenticators failed: {result.get("failed", 0)}')
        self.stdout.write(f'Mappers created: {result.get("mappers_created", 0)}')
        self.stdout.write(f'Mappers updated: {result.get("mappers_updated", 0)}')
        self.stdout.write(f'Mappers failed: {result.get("mappers_failed", 0)}')
