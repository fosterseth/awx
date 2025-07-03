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

        # Process mappers for successfully created/updated authenticators
        mappers_created = 0
        mappers_updated = 0
        mappers_failed = 0
        if created_authenticators:
            self._write_output('\n=== Processing Authenticator Mappers ===', 'success')
            for config in created_authenticators:
                mapper_result = self._process_gateway_mappers(config)
                mappers_created += mapper_result['created']
                mappers_updated += mapper_result['updated']
                mappers_failed += mapper_result['failed']

        return {
            'created': len(created_authenticators),
            'failed': len(configs) - len(created_authenticators),
            'mappers_created': mappers_created,
            'mappers_updated': mappers_updated,
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

    def submit_authenticator(self, gateway_config, ignore_keys=[], config={}):
        """
        Submit an authenticator to Gateway - either create new or update existing.

        Args:
            gateway_config: Complete Gateway authenticator configuration
            ignore_keys: List of configuration keys to ignore during comparison
            config: Optional AWX config dict to store result data

        Returns:
            bool: True if authenticator was submitted successfully, False otherwise
        """
        authenticator_slug = gateway_config.get('slug')
        if not authenticator_slug:
            self._write_output('Gateway config missing slug, cannot submit authenticator', 'error')
            return False

        try:
            # Check if authenticator already exists by slug
            existing_authenticator = self.gateway_client.get_authenticator_by_slug(authenticator_slug)

            if existing_authenticator:
                # Authenticator exists, check if configuration matches
                authenticator_id = existing_authenticator.get('id')

                configs_match, differences = self._authenticator_configs_match(existing_authenticator, gateway_config, ignore_keys)

                if configs_match:
                    self._write_output(f'⚠ Authenticator already exists with matching configuration (ID: {authenticator_id})', 'warning')
                    # Store the existing result for mapper creation
                    config['gateway_authenticator_id'] = authenticator_id
                    config['gateway_authenticator'] = existing_authenticator
                    return True
                else:
                    self._write_output(f'⚠ Authenticator exists but configuration differs (ID: {authenticator_id})', 'warning')
                    self._write_output('  Configuration comparison:')

                    # Log differences between the existing and the new configuration in case of an update
                    for difference in differences:
                        self._write_output(f'    {difference}')

                    # Update the existing authenticator
                    self._write_output('  Updating authenticator with new configuration...')
                    try:
                        # Don't include the slug in the update since it shouldn't change
                        update_config = gateway_config.copy()
                        if 'slug' in update_config:
                            del update_config['slug']

                        result = self.gateway_client.update_authenticator(authenticator_id, update_config)
                        self._write_output(f'✓ Successfully updated authenticator with ID: {authenticator_id}', 'success')

                        # Store the updated result for mapper creation
                        config['gateway_authenticator_id'] = authenticator_id
                        config['gateway_authenticator'] = result
                        return True
                    except GatewayAPIError as e:
                        self._write_output(f'✗ Failed to update authenticator: {e.message}', 'error')
                        if e.response_data:
                            self._write_output(f'  Details: {e.response_data}', 'error')
                        return False
            else:
                # Authenticator doesn't exist, create it
                self._write_output('Creating new authenticator...')

                # Create the authenticator
                result = self.gateway_client.create_authenticator(gateway_config)

                self._write_output(f'✓ Successfully created authenticator with ID: {result.get("id")}', 'success')

                # Store the result for potential mapper creation later
                config['gateway_authenticator_id'] = result.get('id')
                config['gateway_authenticator'] = result
                return True

        except GatewayAPIError as e:
            self._write_output(f'✗ Failed to submit authenticator: {e.message}', 'error')
            if e.response_data:
                self._write_output(f'  Details: {e.response_data}', 'error')
            return False
        except Exception as e:
            self._write_output(f'✗ Unexpected error submitting authenticator: {str(e)}', 'error')
            return False

    def _authenticator_configs_match(self, existing_auth, new_config, ignore_keys=[]):
        """
        Compare existing authenticator configuration with new configuration.

        Args:
            existing_auth: Existing authenticator data from Gateway
            new_config: New authenticator configuration to be created
            ignore_keys: List of configuration keys to ignore during comparison
                        (e.g., ['CALLBACK_URL'] for auto-generated fields)

        Returns:
            bool: True if configurations match, False otherwise
        """

        # Keep track of the differences between the existing and the new configuration
        # Logging them makes debugging much easier
        differences = []

        if existing_auth.get('name') != new_config.get('name'):
            differences.append(f' name: existing="{existing_auth.get("name")}" vs new="{new_config.get("name")}"')
        elif existing_auth.get('type') != new_config.get('type'):
            differences.append(f' type: existing="{existing_auth.get("type")}" vs new="{new_config.get("type")}"')
        elif existing_auth.get('enabled') != new_config.get('enabled'):
            differences.append(f' enabled: existing="{existing_auth.get("enabled")}" vs new="{new_config.get("enabled")}"')
        elif existing_auth.get('create_objects') != new_config.get('create_objects'):
            differences.append(f' create_objects: existing="{existing_auth.get("create_objects")}" vs new="{new_config.get("create_objects")}"')
        elif existing_auth.get('remove_users') != new_config.get('remove_users'):
            differences.append(f' create_objects: existing="{existing_auth.get("remove_users")}" vs new="{new_config.get("remove_users")}"')

        # Compare configuration section
        existing_config = existing_auth.get('configuration', {})
        new_config_section = new_config.get('configuration', {})

        # Helper function to check if a key should be ignored
        def should_ignore_key(config_key):
            return config_key in ignore_keys

        # Check if all keys in new config exist in existing config with same values
        for key, value in new_config_section.items():
            if should_ignore_key(key):
                continue
            if key not in existing_config:
                differences.append(f' {key}: existing=<missing> vs new="{value}"')
            elif existing_config[key] != value:
                differences.append(f' {key}: existing="{existing_config.get(key)}" vs new="{value}"')

        # Check if existing config has extra keys that new config doesn't have
        # (this might indicate configuration drift), but ignore keys in ignore_keys
        for key in existing_config:
            if should_ignore_key(key):
                continue
            if key not in new_config_section:
                differences.append(f' {key}: existing="{existing_config.get(key)}" vs new=<missing>')

        return len(differences) == 0, differences

    def _compare_mapper_lists(self, existing_mappers, new_mappers, ignore_keys=None):
        """
        Compare existing and new mapper lists to determine which need updates vs creation.

        Args:
            existing_mappers: List of existing mapper configurations from Gateway
            new_mappers: List of new mapper configurations to be created/updated
            ignore_keys: List of keys to ignore during comparison (e.g., auto-generated fields)

        Returns:
            tuple: (mappers_to_update, mappers_to_create)
                mappers_to_update: List of tuples (existing_mapper, new_mapper) for updates
                mappers_to_create: List of new_mapper configs that don't match any existing
        """
        if ignore_keys is None:
            ignore_keys = []

        mappers_to_update = []
        mappers_to_create = []

        for new_mapper in new_mappers:
            matched_existing = None

            # Try to find a matching existing mapper
            for existing_mapper in existing_mappers:
                if self._mappers_match_structurally(existing_mapper, new_mapper, ignore_keys):
                    matched_existing = existing_mapper
                    break

            if matched_existing:
                # Check if the configuration actually differs (ignoring auto-generated fields)
                if not self._mapper_configs_match(matched_existing, new_mapper, ignore_keys):
                    mappers_to_update.append((matched_existing, new_mapper))
                # If configs match exactly, no action needed (mapper is up to date)
            else:
                # No matching existing mapper found, needs to be created
                mappers_to_create.append(new_mapper)

        return mappers_to_update, mappers_to_create

    def _mappers_match_structurally(self, existing_mapper, new_mapper, ignore_keys=None):
        """
        Check if two mappers match structurally (same organization, team, map_type, role).
        This identifies if they represent the same logical mapping.

        Args:
            existing_mapper: Existing mapper configuration from Gateway
            new_mapper: New mapper configuration
            ignore_keys: List of keys to ignore during comparison

        Returns:
            bool: True if mappers represent the same logical mapping
        """
        if ignore_keys is None:
            ignore_keys = []

        # Compare key structural fields that identify the same logical mapper
        structural_fields = ['organization', 'team', 'map_type', 'role']

        for field in structural_fields:
            if existing_mapper.get(field) != new_mapper.get(field):
                return False

        return True

    def _mapper_configs_match(self, existing_mapper, new_mapper, ignore_keys=None):
        """
        Compare mapper configurations to check if they are identical.

        Args:
            existing_mapper: Existing mapper configuration from Gateway
            new_mapper: New mapper configuration
            ignore_keys: List of keys to ignore during comparison

        Returns:
            bool: True if configurations match, False otherwise
        """
        if ignore_keys is None:
            ignore_keys = []

        # Helper function to check if a key should be ignored
        def should_ignore_key(config_key):
            return config_key in ignore_keys

        # Compare all mapper fields except ignored ones
        all_keys = set(existing_mapper.keys()) | set(new_mapper.keys())

        for key in all_keys:
            if should_ignore_key(key):
                continue

            existing_value = existing_mapper.get(key)
            new_value = new_mapper.get(key)

            if existing_value != new_value:
                return False

        return True

    def _process_gateway_mappers(self, config):
        """Process authenticator mappers in Gateway from AWX config - create or update as needed."""
        authenticator_id = config.get('gateway_authenticator_id')
        if not authenticator_id:
            self._write_output(f'No authenticator ID found for {config["category"]}, skipping mappers', 'error')
            return {'created': 0, 'updated': 0, 'failed': 0}

        category = config['category']
        org_mappers = config.get('org_mappers', [])
        team_mappers = config.get('team_mappers', [])
        all_new_mappers = org_mappers + team_mappers

        if len(all_new_mappers) == 0:
            self._write_output(f'No mappers to process for {category} authenticator')
            return {'created': 0, 'updated': 0, 'failed': 0}

        self._write_output(f'\n--- Processing mappers for {category} authenticator (ID: {authenticator_id}) ---')
        self._write_output(f'Organization mappers: {len(org_mappers)}')
        self._write_output(f'Team mappers: {len(team_mappers)}')

        # Get existing mappers from Gateway
        try:
            existing_mappers = self.gateway_client.get_authenticator_maps(authenticator_id)
        except GatewayAPIError as e:
            self._write_output(f'Failed to retrieve existing mappers: {e.message}', 'error')
            return {'created': 0, 'updated': 0, 'failed': len(all_new_mappers)}

        # Define mapper-specific ignore keys (can be overridden by subclasses)
        ignore_keys = self._get_mapper_ignore_keys()

        # Compare existing vs new mappers
        mappers_to_update, mappers_to_create = self._compare_mapper_lists(existing_mappers, all_new_mappers, ignore_keys)

        created_count = 0
        updated_count = 0
        failed_count = 0

        # Process updates
        for existing_mapper, new_mapper in mappers_to_update:
            if self._update_single_mapper(existing_mapper, new_mapper):
                updated_count += 1
            else:
                failed_count += 1

        # Process creations
        for new_mapper in mappers_to_create:
            mapper_type = new_mapper.get('map_type', 'unknown')
            if self._create_single_mapper(authenticator_id, new_mapper, mapper_type):
                created_count += 1
            else:
                failed_count += 1

        # Summary
        self._write_output(f'Mappers created: {created_count}, updated: {updated_count}, failed: {failed_count}')
        return {'created': created_count, 'updated': updated_count, 'failed': failed_count}

    def _get_mapper_ignore_keys(self):
        """
        Get list of mapper keys to ignore during comparison.
        Can be overridden by subclasses for mapper-specific ignore keys.

        Returns:
            list: List of keys to ignore (e.g., auto-generated fields)
        """
        return ['id', 'authenticator', 'created', 'modified', 'summary_fields', 'modified_by', 'created_by', 'related', 'url']

    def _update_single_mapper(self, existing_mapper, new_mapper):
        """Update a single mapper in Gateway.

        Args:
            existing_mapper: Existing mapper data from Gateway
            new_mapper: New mapper configuration to update to

        Returns:
            bool: True if mapper was updated successfully, False otherwise
        """
        try:
            mapper_id = existing_mapper.get('id')
            if not mapper_id:
                self._write_output('  ✗ Existing mapper missing ID, cannot update', 'error')
                return False

            # Prepare update config - don't include fields that shouldn't be updated
            update_config = new_mapper.copy()

            # Remove fields that shouldn't be updated (read-only or auto-generated)
            fields_to_remove = ['id', 'authenticator', 'created', 'modified']
            for field in fields_to_remove:
                update_config.pop(field, None)

            # Update the mapper
            self.gateway_client.update_authenticator_map(mapper_id, update_config)

            mapper_name = new_mapper.get('name', 'Unknown')
            self._write_output(f'  ✓ Updated mapper: {mapper_name}', 'success')
            return True

        except GatewayAPIError as e:
            mapper_name = new_mapper.get('name', 'Unknown')
            self._write_output(f'  ✗ Failed to update mapper "{mapper_name}": {e.message}', 'error')
            if e.response_data:
                self._write_output(f'    Details: {e.response_data}', 'error')
            return False
        except Exception as e:
            mapper_name = new_mapper.get('name', 'Unknown')
            self._write_output(f'  ✗ Unexpected error updating mapper "{mapper_name}": {str(e)}', 'error')
            return False

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
