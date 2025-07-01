"""
Base authenticator migrator class.

This module defines the contract that all specific authenticator migrators must follow.
"""

from awx.main.utils.gateway_client import GatewayAPIError
import re
import hashlib


class BaseAuthenticatorMigrator:
    """
    Base class for all authenticator migrators.
    Defines the contract that all specific authenticator migrators must follow.
    """

    def __init__(self, gateway_client=None, command=None):
        """
        Initialize the authenticator migrator.

        Args:
            gateway_client: GatewayClient instance for API calls
            command: Optional Django management command instance (for styled output)
        """
        self.gateway_client = gateway_client
        self.command = command

    def migrate(self):
        """
        Main entry point - orchestrates the migration process.

        Returns:
            dict: Summary of migration results
        """
        # Get configuration from AWX/Controller
        configs = self.get_controller_config()

        if not configs:
            self._write_output(f'No {self.get_authenticator_type()} authenticators found to migrate.', 'warning')
            return {'created': 0, 'failed': 0, 'mappers_created': 0, 'mappers_failed': 0}

        self._write_output(f'Found {len(configs)} {self.get_authenticator_type()} authentication configuration(s).', 'success')

        # Process each authenticator configuration
        created_authenticators = []
        for config in configs:
            if self.create_gateway_authenticator(config):
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
            'failed': len(configs) - len(created_authenticators),
            'mappers_created': mappers_created,
            'mappers_failed': mappers_failed,
        }

    def get_controller_config(self):
        """
        Gather configuration from AWX/Controller.

        Returns:
            list: List of configuration dictionaries
        """
        raise NotImplementedError("Subclasses must implement get_controller_config()")

    def create_gateway_authenticator(self, config):
        """
        Create authenticator in Gateway.

        Args:
            config: Configuration dictionary from get_controller_config()

        Returns:
            bool: True if authenticator was created successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement create_gateway_authenticator()")

    def get_authenticator_type(self):
        """
        Get the human-readable authenticator type name.

        Returns:
            str: Authenticator type name for logging
        """
        raise NotImplementedError("Subclasses must implement get_authenticator_type()")

    def _generate_authenticator_slug(self, auth_type, category, identifier):
        """Generate a deterministic slug for an authenticator."""
        base_string = f"awx-{auth_type}-{category}-{identifier}"
        cleaned = re.sub(r'[^a-zA-Z0-9]+', '-', base_string.lower())
        cleaned = re.sub(r'^-+|-+$', '', cleaned)
        cleaned = re.sub(r'-+', '-', cleaned)
        slug_hash = hashlib.md5(cleaned.encode('utf-8')).hexdigest()[:8]
        final_slug = f"awx-{auth_type}-{slug_hash}"
        return final_slug

    def _create_gateway_mappers(self, config):
        """Create authenticator mappers in Gateway from AWX config."""
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
        """Create a single mapper in Gateway."""
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
