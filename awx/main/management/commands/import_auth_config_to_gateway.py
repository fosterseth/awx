import sys
import os

from django.core.management.base import BaseCommand
from awx.sso.utils.github_migrator import GitHubMigrator
from awx.sso.utils.oidc_migrator import OIDCMigrator
from awx.main.utils.gateway_client import GatewayClient, GatewayAPIError


class Command(BaseCommand):
    help = 'Import existing auth provider configurations to AAP Gateway via API requests'

    def add_arguments(self, parser):
        parser.add_argument('--skip-oidc', action='store_true', help='Skip importing GitHub and generic OIDC authenticators')
        parser.add_argument('--skip-ldap', action='store_true', help='Skip importing LDAP authenticators')

    def handle(self, *args, **options):
        # Read Gateway connection parameters from environment variables
        gateway_base_url = os.getenv('GATEWAY_BASE_URL')
        gateway_user = os.getenv('GATEWAY_USER')
        gateway_password = os.getenv('GATEWAY_PASSWORD')
        gateway_skip_verify = os.getenv('GATEWAY_SKIP_VERIFY', '').lower() in ('true', '1', 'yes', 'on')

        skip_oidc = options['skip_oidc']
        # skip_ldap = options['skip_ldap']

        # If the management command isn't called with all parameters needed to talk to Gateway, consider
        # it a dry-run and exit cleanly
        if not gateway_base_url or not gateway_user or not gateway_password:
            self.stdout.write(self.style.WARNING('Missing required environment variables:'))
            self.stdout.write(self.style.WARNING('- GATEWAY_BASE_URL: Base URL of the AAP Gateway instance'))
            self.stdout.write(self.style.WARNING('- GATEWAY_USER: Username for AAP Gateway authentication'))
            self.stdout.write(self.style.WARNING('- GATEWAY_PASSWORD: Password for AAP Gateway authentication'))
            self.stdout.write(self.style.WARNING('- GATEWAY_SKIP_VERIFY: Skip SSL certificate verification (optional)'))
            sys.exit(0)

        self.stdout.write(self.style.SUCCESS(f'Gateway Base URL: {gateway_base_url}'))
        self.stdout.write(self.style.SUCCESS(f'Gateway User: {gateway_user}'))
        self.stdout.write(self.style.SUCCESS(f'Gateway Password: {"*" * len(gateway_password)}'))
        self.stdout.write(self.style.SUCCESS(f'Skip SSL Verification: {gateway_skip_verify}'))

        # Create Gateway client and run migrations
        try:
            self.stdout.write(self.style.SUCCESS('\n=== Connecting to Gateway ==='))

            with GatewayClient(base_url=gateway_base_url, username=gateway_user, password=gateway_password, skip_verify=gateway_skip_verify) as gateway_client:

                self.stdout.write(self.style.SUCCESS('Successfully connected to Gateway'))

                # Initialize migrators
                migrators = []
                if not skip_oidc:
                    migrators.append(GitHubMigrator(gateway_client, self))
                    migrators.append(OIDCMigrator(gateway_client, self))
                # if not skip_ldap:
                #     migrators.append(LDAPMigrator(gateway_client, self))

                # Run migrations
                total_results = {
                    'created': 0,
                    'failed': 0,
                    'mappers_created': 0,
                    'mappers_failed': 0,
                }

                if not migrators:
                    self.stdout.write(self.style.WARNING('No authentication configurations found to migrate.'))
                else:
                    for migrator in migrators:
                        self.stdout.write(self.style.SUCCESS(f'\n=== Migrating {migrator.get_authenticator_type()} Configurations ==='))
                        result = migrator.migrate()
                        self._print_export_summary(migrator.get_authenticator_type(), result)

                        # Accumulate results
                        for key in total_results:
                            total_results[key] += result.get(key, 0)

                    # Overall summary
                    self.stdout.write(self.style.SUCCESS('\n=== Migration Summary ==='))
                    self.stdout.write(f'Total authenticators created: {total_results["created"]}')
                    self.stdout.write(f'Total authenticators failed: {total_results["failed"]}')
                    self.stdout.write(f'Total mappers created: {total_results["mappers_created"]}')
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
        self.stdout.write(f'Authenticators created: {result["created"]}')
        self.stdout.write(f'Authenticators failed: {result["failed"]}')
        self.stdout.write(f'Mappers created: {result["mappers_created"]}')
        self.stdout.write(f'Mappers failed: {result["mappers_failed"]}')
