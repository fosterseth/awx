"""
Unit tests for base authenticator migrator functionality.
"""

import pytest
from unittest.mock import Mock
from awx.sso.utils.base_migrator import BaseAuthenticatorMigrator


class TestBaseAuthenticatorMigrator:
    """Tests for BaseAuthenticatorMigrator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.gateway_client = Mock()
        self.command = Mock()
        self.migrator = BaseAuthenticatorMigrator(self.gateway_client, self.command)

    def test_generate_authenticator_slug(self):
        """Test slug generation is deterministic."""
        slug1 = self.migrator._generate_authenticator_slug('github', 'github-org', 'client123')
        slug2 = self.migrator._generate_authenticator_slug('github', 'github-org', 'client123')

        assert slug1 == slug2
        assert slug1.startswith('awx-github-')
        assert len(slug1.split('-')[-1]) == 8  # Hash should be 8 characters

    def test_generate_authenticator_slug_different_inputs(self):
        """Test that different inputs generate different slugs."""
        slug1 = self.migrator._generate_authenticator_slug('github', 'github-org', 'client123')
        slug2 = self.migrator._generate_authenticator_slug('github', 'github-org', 'client456')
        slug3 = self.migrator._generate_authenticator_slug('ldap', 'ldap', 'ldap://server')

        assert slug1 != slug2
        assert slug1 != slug3
        assert slug2 != slug3

    def test_get_mapper_ignore_keys_default(self):
        """Test default mapper ignore keys."""
        ignore_keys = self.migrator._get_mapper_ignore_keys()

        expected_keys = ['id', 'authenticator', 'created', 'modified', 'summary_fields', 'modified_by', 'created_by', 'related', 'url']
        assert ignore_keys == expected_keys


class TestAuthenticatorConfigComparison:
    """Tests for authenticator configuration comparison methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.gateway_client = Mock()
        self.command = Mock()
        self.migrator = BaseAuthenticatorMigrator(self.gateway_client, self.command)

    def test_authenticator_configs_match_identical(self):
        """Test that identical configurations match."""
        existing_auth = {
            'name': 'GitHub Auth',
            'type': 'ansible_base.authentication.authenticator_plugins.github',
            'enabled': True,
            'create_objects': True,
            'remove_users': False,
            'configuration': {'KEY': 'client123', 'SECRET': 'secret456'},
        }

        new_config = existing_auth.copy()
        new_config['configuration'] = existing_auth['configuration'].copy()

        assert self.migrator._authenticator_configs_match(existing_auth, new_config) == (True, [])

    def test_authenticator_configs_match_with_ignore_keys(self):
        """Test that configurations match when ignoring specified keys."""
        existing_auth = {
            'name': 'GitHub Auth',
            'type': 'ansible_base.authentication.authenticator_plugins.github',
            'enabled': True,
            'create_objects': True,
            'remove_users': False,
            'configuration': {'KEY': 'client123', 'SECRET': 'secret456', 'CALLBACK_URL': 'https://gateway.example.com/callback'},
        }

        new_config = {
            'name': 'GitHub Auth',
            'type': 'ansible_base.authentication.authenticator_plugins.github',
            'enabled': True,
            'create_objects': True,
            'remove_users': False,
            'configuration': {'KEY': 'client123', 'SECRET': 'secret456'},
        }

        # Should not match without ignore keys
        assert self.migrator._authenticator_configs_match(existing_auth, new_config) == (
            False,
            [' CALLBACK_URL: existing="https://gateway.example.com/callback" vs new=<missing>'],
        )

        # Should match when ignoring CALLBACK_URL
        ignore_keys = ['CALLBACK_URL']
        assert self.migrator._authenticator_configs_match(existing_auth, new_config, ignore_keys) == (True, [])

    def test_authenticator_configs_different_basic_fields(self):
        """Test that configurations don't match when basic fields differ."""
        existing_auth = {
            'name': 'GitHub Auth',
            'type': 'ansible_base.authentication.authenticator_plugins.github',
            'enabled': True,
            'create_objects': True,
            'remove_users': False,
            'configuration': {'KEY': 'client123', 'SECRET': 'secret456'},
        }

        # Test different name
        new_config = existing_auth.copy()
        new_config['name'] = 'Different GitHub Auth'
        match, differences = self.migrator._authenticator_configs_match(existing_auth, new_config)
        assert match is False
        assert len(differences) == 1
        assert 'name:' in differences[0]

        # Test different type
        new_config = existing_auth.copy()
        new_config['type'] = 'ansible_base.authentication.authenticator_plugins.ldap'
        match, differences = self.migrator._authenticator_configs_match(existing_auth, new_config)
        assert match is False
        assert len(differences) == 1
        assert 'type:' in differences[0]

        # Test different enabled
        new_config = existing_auth.copy()
        new_config['enabled'] = False
        match, differences = self.migrator._authenticator_configs_match(existing_auth, new_config)
        assert match is False
        assert len(differences) == 1
        assert 'enabled:' in differences[0]

    def test_authenticator_configs_different_configuration(self):
        """Test that configurations don't match when configuration section differs."""
        existing_auth = {
            'name': 'GitHub Auth',
            'type': 'ansible_base.authentication.authenticator_plugins.github',
            'enabled': True,
            'create_objects': True,
            'remove_users': False,
            'configuration': {'KEY': 'client123', 'SECRET': 'secret456', 'SCOPE': 'read:org'},
        }

        # Test different KEY
        new_config = existing_auth.copy()
        new_config['configuration'] = {'KEY': 'client789', 'SECRET': 'secret456', 'SCOPE': 'read:org'}
        match, differences = self.migrator._authenticator_configs_match(existing_auth, new_config)
        assert match is False
        assert len(differences) == 1
        assert 'KEY:' in differences[0]
        assert 'existing="client123"' in differences[0]
        assert 'new="client789"' in differences[0]

        # Test missing key in new config
        new_config = existing_auth.copy()
        new_config['configuration'] = {'KEY': 'client123', 'SECRET': 'secret456'}
        match, differences = self.migrator._authenticator_configs_match(existing_auth, new_config)
        assert match is False
        assert len(differences) == 1
        assert 'SCOPE:' in differences[0]
        assert 'vs new=<missing>' in differences[0]

        # Test extra key in new config
        new_config = existing_auth.copy()
        new_config['configuration'] = {'KEY': 'client123', 'SECRET': 'secret456', 'SCOPE': 'read:org', 'EXTRA_KEY': 'extra_value'}
        match, differences = self.migrator._authenticator_configs_match(existing_auth, new_config)
        assert match is False
        assert len(differences) == 1
        assert 'EXTRA_KEY:' in differences[0]
        assert 'existing=<missing>' in differences[0]

    def test_authenticator_configs_differences_details(self):
        """Test that difference tracking provides detailed information."""
        existing_auth = {
            'name': 'GitHub Auth',
            'type': 'ansible_base.authentication.authenticator_plugins.github',
            'enabled': True,
            'create_objects': True,
            'remove_users': False,
            'configuration': {'KEY': 'client123', 'SECRET': 'secret456', 'SCOPE': 'read:org', 'CALLBACK_URL': 'https://gateway.example.com/callback'},
        }

        # Test multiple differences with ignore keys
        new_config = {
            'name': 'GitHub Auth',
            'type': 'ansible_base.authentication.authenticator_plugins.github',
            'enabled': True,
            'create_objects': True,
            'remove_users': False,
            'configuration': {
                'KEY': 'client456',  # Different value
                'SECRET': 'newsecret',  # Different value
                'SCOPE': 'read:org',  # Same value
                # CALLBACK_URL missing (but ignored)
                'NEW_FIELD': 'new_value',  # Extra field
            },
        }

        ignore_keys = ['CALLBACK_URL']
        match, differences = self.migrator._authenticator_configs_match(existing_auth, new_config, ignore_keys)

        assert match is False
        assert len(differences) == 3  # KEY, SECRET, NEW_FIELD

        # Check that all expected differences are captured
        difference_text = ' '.join(differences)
        assert 'KEY:' in difference_text
        assert 'SECRET:' in difference_text
        assert 'NEW_FIELD:' in difference_text
        assert 'CALLBACK_URL' not in difference_text  # Should be ignored


class TestMapperComparison:
    """Tests for mapper comparison methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.gateway_client = Mock()
        self.command = Mock()
        self.migrator = BaseAuthenticatorMigrator(self.gateway_client, self.command)

    def test_mappers_match_structurally_identical(self):
        """Test that identical mappers match structurally."""
        mapper1 = {'organization': 'myorg', 'team': 'engineering', 'map_type': 'team', 'role': 'Team Member'}

        mapper2 = mapper1.copy()

        assert self.migrator._mappers_match_structurally(mapper1, mapper2) is True

    def test_mappers_match_structurally_different_fields(self):
        """Test that mappers don't match structurally when key fields differ."""
        base_mapper = {'organization': 'myorg', 'team': 'engineering', 'map_type': 'team', 'role': 'Team Member'}

        # Test different organization
        mapper2 = base_mapper.copy()
        mapper2['organization'] = 'otherorg'
        assert self.migrator._mappers_match_structurally(base_mapper, mapper2) is False

        # Test different team
        mapper2 = base_mapper.copy()
        mapper2['team'] = 'qa'
        assert self.migrator._mappers_match_structurally(base_mapper, mapper2) is False

        # Test different map_type
        mapper2 = base_mapper.copy()
        mapper2['map_type'] = 'organization'
        assert self.migrator._mappers_match_structurally(base_mapper, mapper2) is False

        # Test different role
        mapper2 = base_mapper.copy()
        mapper2['role'] = 'Organization Admin'
        assert self.migrator._mappers_match_structurally(base_mapper, mapper2) is False

    def test_mapper_configs_match_identical(self):
        """Test that identical mapper configurations match."""
        mapper1 = {
            'name': 'myorg - engineering',
            'organization': 'myorg',
            'team': 'engineering',
            'map_type': 'team',
            'role': 'Team Member',
            'order': 1,
            'triggers': {'groups': {'has_or': ['engineers']}},
            'revoke': False,
        }

        mapper2 = mapper1.copy()

        assert self.migrator._mapper_configs_match(mapper1, mapper2) is True

    def test_mapper_configs_match_with_ignore_keys(self):
        """Test that mapper configurations match when ignoring specified keys."""
        existing_mapper = {
            'id': 123,
            'authenticator': 456,
            'name': 'myorg - engineering',
            'organization': 'myorg',
            'team': 'engineering',
            'map_type': 'team',
            'role': 'Team Member',
            'order': 1,
            'triggers': {'groups': {'has_or': ['engineers']}},
            'revoke': False,
            'created': '2023-01-01T00:00:00Z',
            'modified': '2023-01-01T00:00:00Z',
        }

        new_mapper = {
            'name': 'myorg - engineering',
            'organization': 'myorg',
            'team': 'engineering',
            'map_type': 'team',
            'role': 'Team Member',
            'order': 1,
            'triggers': {'groups': {'has_or': ['engineers']}},
            'revoke': False,
        }

        # Should not match without ignore keys
        assert self.migrator._mapper_configs_match(existing_mapper, new_mapper) is False

        # Should match when ignoring auto-generated fields
        ignore_keys = ['id', 'authenticator', 'created', 'modified']
        assert self.migrator._mapper_configs_match(existing_mapper, new_mapper, ignore_keys) is True

    def test_mapper_configs_different_values(self):
        """Test that mapper configurations don't match when values differ."""
        mapper1 = {
            'name': 'myorg - engineering',
            'organization': 'myorg',
            'team': 'engineering',
            'map_type': 'team',
            'role': 'Team Member',
            'order': 1,
            'triggers': {'groups': {'has_or': ['engineers']}},
            'revoke': False,
        }

        # Test different name
        mapper2 = mapper1.copy()
        mapper2['name'] = 'myorg - qa'
        assert self.migrator._mapper_configs_match(mapper1, mapper2) is False

        # Test different order
        mapper2 = mapper1.copy()
        mapper2['order'] = 2
        assert self.migrator._mapper_configs_match(mapper1, mapper2) is False

        # Test different triggers
        mapper2 = mapper1.copy()
        mapper2['triggers'] = {'groups': {'has_or': ['qa-team']}}
        assert self.migrator._mapper_configs_match(mapper1, mapper2) is False

        # Test different revoke
        mapper2 = mapper1.copy()
        mapper2['revoke'] = True
        assert self.migrator._mapper_configs_match(mapper1, mapper2) is False


class TestCompareMapperLists:
    """Tests for _compare_mapper_lists method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.gateway_client = Mock()
        self.command = Mock()
        self.migrator = BaseAuthenticatorMigrator(self.gateway_client, self.command)

    def test_compare_mapper_lists_empty(self):
        """Test comparing empty mapper lists."""
        existing_mappers = []
        new_mappers = []

        mappers_to_update, mappers_to_create = self.migrator._compare_mapper_lists(existing_mappers, new_mappers)

        assert mappers_to_update == []
        assert mappers_to_create == []

    def test_compare_mapper_lists_all_new(self):
        """Test when all new mappers need to be created."""
        existing_mappers = []
        new_mappers = [
            {
                'name': 'myorg - engineering',
                'organization': 'myorg',
                'team': 'engineering',
                'map_type': 'team',
                'role': 'Team Member',
                'order': 1,
                'triggers': {'groups': {'has_or': ['engineers']}},
                'revoke': False,
            },
            {
                'name': 'myorg - qa',
                'organization': 'myorg',
                'team': 'qa',
                'map_type': 'team',
                'role': 'Team Member',
                'order': 2,
                'triggers': {'groups': {'has_or': ['qa-team']}},
                'revoke': False,
            },
        ]

        mappers_to_update, mappers_to_create = self.migrator._compare_mapper_lists(existing_mappers, new_mappers)

        assert mappers_to_update == []
        assert mappers_to_create == new_mappers

    def test_compare_mapper_lists_all_existing_match(self):
        """Test when all existing mappers match exactly."""
        existing_mappers = [
            {
                'id': 123,
                'authenticator': 456,
                'name': 'myorg - engineering',
                'organization': 'myorg',
                'team': 'engineering',
                'map_type': 'team',
                'role': 'Team Member',
                'order': 1,
                'triggers': {'groups': {'has_or': ['engineers']}},
                'revoke': False,
                'created': '2023-01-01T00:00:00Z',
                'modified': '2023-01-01T00:00:00Z',
            }
        ]

        new_mappers = [
            {
                'name': 'myorg - engineering',
                'organization': 'myorg',
                'team': 'engineering',
                'map_type': 'team',
                'role': 'Team Member',
                'order': 1,
                'triggers': {'groups': {'has_or': ['engineers']}},
                'revoke': False,
            }
        ]

        ignore_keys = ['id', 'authenticator', 'created', 'modified']
        mappers_to_update, mappers_to_create = self.migrator._compare_mapper_lists(existing_mappers, new_mappers, ignore_keys)

        assert mappers_to_update == []
        assert mappers_to_create == []

    def test_compare_mapper_lists_needs_update(self):
        """Test when existing mappers need updates."""
        existing_mappers = [
            {
                'id': 123,
                'authenticator': 456,
                'name': 'myorg - engineering',
                'organization': 'myorg',
                'team': 'engineering',
                'map_type': 'team',
                'role': 'Team Member',
                'order': 1,
                'triggers': {'groups': {'has_or': ['old-engineers']}},
                'revoke': False,
                'created': '2023-01-01T00:00:00Z',
                'modified': '2023-01-01T00:00:00Z',
            }
        ]

        new_mappers = [
            {
                'name': 'myorg - engineering',
                'organization': 'myorg',
                'team': 'engineering',
                'map_type': 'team',
                'role': 'Team Member',
                'order': 1,
                'triggers': {'groups': {'has_or': ['new-engineers']}},
                'revoke': False,
            }
        ]

        ignore_keys = ['id', 'authenticator', 'created', 'modified']
        mappers_to_update, mappers_to_create = self.migrator._compare_mapper_lists(existing_mappers, new_mappers, ignore_keys)

        assert len(mappers_to_update) == 1
        assert mappers_to_update[0] == (existing_mappers[0], new_mappers[0])
        assert mappers_to_create == []

    def test_compare_mapper_lists_mixed_operations(self):
        """Test mix of updates and creates."""
        existing_mappers = [
            {
                'id': 123,
                'authenticator': 456,
                'name': 'myorg - engineering',
                'organization': 'myorg',
                'team': 'engineering',
                'map_type': 'team',
                'role': 'Team Member',
                'order': 1,
                'triggers': {'groups': {'has_or': ['old-engineers']}},
                'revoke': False,
                'created': '2023-01-01T00:00:00Z',
                'modified': '2023-01-01T00:00:00Z',
            }
        ]

        new_mappers = [
            {
                'name': 'myorg - engineering',
                'organization': 'myorg',
                'team': 'engineering',
                'map_type': 'team',
                'role': 'Team Member',
                'order': 1,
                'triggers': {'groups': {'has_or': ['new-engineers']}},
                'revoke': False,
            },
            {
                'name': 'myorg - qa',
                'organization': 'myorg',
                'team': 'qa',
                'map_type': 'team',
                'role': 'Team Member',
                'order': 2,
                'triggers': {'groups': {'has_or': ['qa-team']}},
                'revoke': False,
            },
        ]

        ignore_keys = ['id', 'authenticator', 'created', 'modified']
        mappers_to_update, mappers_to_create = self.migrator._compare_mapper_lists(existing_mappers, new_mappers, ignore_keys)

        assert len(mappers_to_update) == 1
        assert mappers_to_update[0] == (existing_mappers[0], new_mappers[0])
        assert len(mappers_to_create) == 1
        assert mappers_to_create[0] == new_mappers[1]

    def test_compare_mapper_lists_no_structural_match(self):
        """Test when existing and new mappers don't match structurally."""
        existing_mappers = [
            {
                'id': 123,
                'authenticator': 456,
                'name': 'myorg - engineering',
                'organization': 'myorg',
                'team': 'engineering',
                'map_type': 'team',
                'role': 'Team Member',
                'order': 1,
                'triggers': {'groups': {'has_or': ['engineers']}},
                'revoke': False,
            }
        ]

        new_mappers = [
            {
                'name': 'otherorg - qa',
                'organization': 'otherorg',  # Different organization
                'team': 'qa',  # Different team
                'map_type': 'team',
                'role': 'Team Member',
                'order': 1,
                'triggers': {'groups': {'has_or': ['qa-team']}},
                'revoke': False,
            }
        ]

        mappers_to_update, mappers_to_create = self.migrator._compare_mapper_lists(existing_mappers, new_mappers)

        assert mappers_to_update == []
        assert mappers_to_create == new_mappers


# Parametrized tests for edge cases
@pytest.mark.parametrize(
    "existing_auth,new_config,ignore_keys,expected_match,expected_differences_count",
    [
        # Test with None values
        ({'name': 'Test', 'configuration': {'KEY': None}}, {'name': 'Test', 'configuration': {'KEY': None}}, [], True, 0),
        # Test with empty configuration
        ({'name': 'Test', 'configuration': {}}, {'name': 'Test', 'configuration': {}}, [], True, 0),
        # Test missing configuration section
        ({'name': 'Test'}, {'name': 'Test'}, [], True, 0),
        # Test with ignore keys matching
        (
            {'name': 'Test', 'configuration': {'KEY': 'value', 'IGNORE_ME': 'old'}},
            {'name': 'Test', 'configuration': {'KEY': 'value', 'IGNORE_ME': 'new'}},
            ['IGNORE_ME'],
            True,
            0,
        ),
        # Test with differences that are not ignored
        (
            {'name': 'Test', 'configuration': {'KEY': 'value1'}},
            {'name': 'Test', 'configuration': {'KEY': 'value2'}},
            [],
            False,
            1,
        ),
    ],
)
def test_authenticator_configs_match_edge_cases(existing_auth, new_config, ignore_keys, expected_match, expected_differences_count):
    """Test edge cases for authenticator configuration matching."""
    gateway_client = Mock()
    command = Mock()
    migrator = BaseAuthenticatorMigrator(gateway_client, command)

    match, differences = migrator._authenticator_configs_match(existing_auth, new_config, ignore_keys)
    assert match == expected_match
    assert len(differences) == expected_differences_count


@pytest.mark.parametrize(
    "mapper1,mapper2,ignore_keys,expected",
    [
        # Test with None team values (org mappers)
        (
            {'organization': 'myorg', 'team': None, 'map_type': 'organization', 'role': 'Organization Admin'},
            {'organization': 'myorg', 'team': None, 'map_type': 'organization', 'role': 'Organization Admin'},
            [],
            True,
        ),
        # Test with ignore keys (for structural matching, ignore_keys shouldn't matter)
        (
            {'organization': 'myorg', 'team': 'eng', 'map_type': 'team', 'role': 'Team Member', 'id': 123},
            {'organization': 'myorg', 'team': 'eng', 'map_type': 'team', 'role': 'Team Member', 'id': 456},
            ['id'],
            True,
        ),
        # Test structural mismatch
        (
            {'organization': 'myorg', 'team': 'eng', 'map_type': 'team', 'role': 'Team Member'},
            {'organization': 'myorg', 'team': 'qa', 'map_type': 'team', 'role': 'Team Member'},
            [],
            False,
        ),
    ],
)
def test_mappers_match_structurally_edge_cases(mapper1, mapper2, ignore_keys, expected):
    """Test edge cases for mapper structural matching."""
    gateway_client = Mock()
    command = Mock()
    migrator = BaseAuthenticatorMigrator(gateway_client, command)

    result = migrator._mappers_match_structurally(mapper1, mapper2, ignore_keys)
    assert result == expected
