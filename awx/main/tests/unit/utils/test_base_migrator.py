"""
Unit tests for base authenticator migrator functionality.
"""

import pytest
from unittest.mock import Mock, patch
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
        slug1 = self.migrator._generate_authenticator_slug('github', 'github-org')
        slug2 = self.migrator._generate_authenticator_slug('github', 'github-org')

        assert slug1 == slug2
        assert slug1 == 'aap-github-github-org'

    def test_generate_authenticator_slug_different_inputs(self):
        """Test that different inputs generate different slugs."""
        slug1 = self.migrator._generate_authenticator_slug('github', 'github-org')
        slug2 = self.migrator._generate_authenticator_slug('github', 'github-team')
        slug3 = self.migrator._generate_authenticator_slug('ldap', 'ldap')

        assert slug1 != slug2
        assert slug1 != slug3
        assert slug2 != slug3
        assert slug1 == 'aap-github-github-org'
        assert slug2 == 'aap-github-github-team'
        assert slug3 == 'aap-ldap-ldap'

    def test_generate_authenticator_slug_ldap_variants(self):
        """Test LDAP authenticator slug generation for all supported variants."""
        # Test all LDAP authenticator naming variants
        ldap_base = self.migrator._generate_authenticator_slug('ldap', 'ldap')
        ldap1 = self.migrator._generate_authenticator_slug('ldap', 'ldap1')
        ldap2 = self.migrator._generate_authenticator_slug('ldap', 'ldap2')
        ldap3 = self.migrator._generate_authenticator_slug('ldap', 'ldap3')
        ldap4 = self.migrator._generate_authenticator_slug('ldap', 'ldap4')
        ldap5 = self.migrator._generate_authenticator_slug('ldap', 'ldap5')

        # Verify correct slug format
        assert ldap_base == 'aap-ldap-ldap'
        assert ldap1 == 'aap-ldap-ldap1'
        assert ldap2 == 'aap-ldap-ldap2'
        assert ldap3 == 'aap-ldap-ldap3'
        assert ldap4 == 'aap-ldap-ldap4'
        assert ldap5 == 'aap-ldap-ldap5'

        # Verify all slugs are unique
        all_slugs = [ldap_base, ldap1, ldap2, ldap3, ldap4, ldap5]
        assert len(all_slugs) == len(set(all_slugs))

    def test_generate_authenticator_slug_github_variants(self):
        """Test GitHub authenticator slug generation for all supported variants."""
        # Test all GitHub authenticator naming variants
        github_base = self.migrator._generate_authenticator_slug('github', 'github')
        github_org = self.migrator._generate_authenticator_slug('github', 'github-org')
        github_team = self.migrator._generate_authenticator_slug('github', 'github-team')
        github_enterprise_org = self.migrator._generate_authenticator_slug('github', 'github-enterprise-org')
        github_enterprise_team = self.migrator._generate_authenticator_slug('github', 'github-enterprise-team')

        # Verify correct slug format
        assert github_base == 'aap-github-github'
        assert github_org == 'aap-github-github-org'
        assert github_team == 'aap-github-github-team'
        assert github_enterprise_org == 'aap-github-github-enterprise-org'
        assert github_enterprise_team == 'aap-github-github-enterprise-team'

        # Verify all slugs are unique
        all_slugs = [github_base, github_org, github_team, github_enterprise_org, github_enterprise_team]
        assert len(all_slugs) == len(set(all_slugs))

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
        assert len(differences) == 2  # KEY, NEW_FIELD  (SECRET shows up only if --force is used)

        # Check that all expected differences are captured
        difference_text = ' '.join(differences)
        assert 'KEY:' in difference_text
        # assert 'SECRET:' in difference_text  # SECRET shows up only if --force is used
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
        mapper1 = {'name': 'myorg - engineering', 'organization': 'myorg', 'team': 'engineering', 'map_type': 'team', 'role': 'Team Member'}

        mapper2 = mapper1.copy()

        assert self.migrator._mappers_match_structurally(mapper1, mapper2) is True

    def test_mappers_match_structurally_different_fields(self):
        """Test that mappers match structurally when only name is the same."""
        base_mapper = {'name': 'myorg - engineering', 'organization': 'myorg', 'team': 'engineering', 'map_type': 'team', 'role': 'Team Member'}

        # Test different organization but same name - should still match
        mapper2 = base_mapper.copy()
        mapper2['organization'] = 'otherorg'
        assert self.migrator._mappers_match_structurally(base_mapper, mapper2) is True

        # Test different team but same name - should still match
        mapper2 = base_mapper.copy()
        mapper2['team'] = 'qa'
        assert self.migrator._mappers_match_structurally(base_mapper, mapper2) is True

        # Test different map_type but same name - should still match
        mapper2 = base_mapper.copy()
        mapper2['map_type'] = 'organization'
        assert self.migrator._mappers_match_structurally(base_mapper, mapper2) is True

        # Test different role but same name - should still match
        mapper2 = base_mapper.copy()
        mapper2['role'] = 'Organization Admin'
        assert self.migrator._mappers_match_structurally(base_mapper, mapper2) is True

        # Test different name - should not match
        mapper2 = base_mapper.copy()
        mapper2['name'] = 'otherorg - qa'
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
    "mapper1,mapper2,expected",
    [
        # Test with same name
        (
            {'name': 'myorg - Organization Admins', 'organization': 'myorg', 'team': None, 'map_type': 'organization', 'role': 'Organization Admin'},
            {'name': 'myorg - Organization Admins', 'organization': 'myorg', 'team': None, 'map_type': 'organization', 'role': 'Organization Admin'},
            True,
        ),
        # Test with same name but different other fields
        (
            {'name': 'myorg - eng', 'organization': 'myorg', 'team': 'eng', 'map_type': 'team', 'role': 'Team Member', 'id': 123},
            {'name': 'myorg - eng', 'organization': 'otherorg', 'team': 'qa', 'map_type': 'organization', 'role': 'Organization Admin', 'id': 456},
            True,
        ),
        # Test with different names
        (
            {'name': 'myorg - eng', 'organization': 'myorg', 'team': 'eng', 'map_type': 'team', 'role': 'Team Member'},
            {'name': 'myorg - qa', 'organization': 'myorg', 'team': 'qa', 'map_type': 'team', 'role': 'Team Member'},
            False,
        ),
        # Test with missing name
        (
            {'organization': 'myorg', 'team': 'eng', 'map_type': 'team', 'role': 'Team Member'},
            {'name': 'myorg - eng', 'organization': 'myorg', 'team': 'eng', 'map_type': 'team', 'role': 'Team Member'},
            False,
        ),
        # Test with both missing name
        (
            {'organization': 'myorg', 'team': 'eng', 'map_type': 'team', 'role': 'Team Member'},
            {'organization': 'myorg', 'team': 'eng', 'map_type': 'team', 'role': 'Team Member'},
            True,
        ),
    ],
)
def test_mappers_match_structurally_edge_cases(mapper1, mapper2, expected):
    """Test edge cases for mapper structural matching based on name."""
    gateway_client = Mock()
    command = Mock()
    migrator = BaseAuthenticatorMigrator(gateway_client, command)

    result = migrator._mappers_match_structurally(mapper1, mapper2)
    assert result == expected


class TestSocialAuthMapFunctions:
    """Test cases for social auth map functions."""

    def setup_method(self):
        """Set up test fixtures."""
        self.gateway_client = Mock()
        self.command_obj = Mock()
        self.migrator = BaseAuthenticatorMigrator(self.gateway_client, self.command_obj)

    @patch('awx.sso.utils.base_migrator.settings')
    def test_get_social_org_map_with_authenticator_specific_setting(self, mock_settings):
        """Test get_social_org_map returns authenticator-specific setting when available."""
        # Set up mock settings
        authenticator_map = {'org1': ['team1', 'team2']}
        global_map = {'global_org': ['global_team']}

        mock_settings.SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP = authenticator_map
        mock_settings.SOCIAL_AUTH_ORGANIZATION_MAP = global_map

        # Mock getattr to return the specific setting
        with patch('awx.sso.utils.base_migrator.getattr') as mock_getattr:
            mock_getattr.side_effect = lambda obj, name, default=None: {
                'SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP': authenticator_map,
                'SOCIAL_AUTH_ORGANIZATION_MAP': global_map,
            }.get(name, default)

            result = self.migrator.get_social_org_map('SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP')

            assert result == authenticator_map
            # Verify it was called with the authenticator-specific setting first
            mock_getattr.assert_any_call(mock_settings, 'SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP', None)

    @patch('awx.sso.utils.base_migrator.settings')
    def test_get_social_org_map_fallback_to_global(self, mock_settings):
        """Test get_social_org_map falls back to global setting when authenticator-specific is empty."""
        # Set up mock settings
        global_map = {'global_org': ['global_team']}

        # Mock getattr to return None for authenticator-specific, global for fallback
        with patch('awx.sso.utils.base_migrator.getattr') as mock_getattr:
            mock_getattr.side_effect = lambda obj, name, default=None: {
                'SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP': None,
                'SOCIAL_AUTH_ORGANIZATION_MAP': global_map,
            }.get(name, default)

            result = self.migrator.get_social_org_map('SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP')

            assert result == global_map
            # Verify both calls were made
            mock_getattr.assert_any_call(mock_settings, 'SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP', None)
            mock_getattr.assert_any_call(mock_settings, 'SOCIAL_AUTH_ORGANIZATION_MAP', {})

    @patch('awx.sso.utils.base_migrator.settings')
    def test_get_social_org_map_empty_dict_fallback(self, mock_settings):
        """Test get_social_org_map returns empty dict when neither setting exists."""
        # Mock getattr to return None for both settings
        with patch('awx.sso.utils.base_migrator.getattr') as mock_getattr:
            mock_getattr.side_effect = lambda obj, name, default=None: {'SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP': None, 'SOCIAL_AUTH_ORGANIZATION_MAP': {}}.get(
                name, default
            )

            result = self.migrator.get_social_org_map('SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP')

            assert result == {}

    @patch('awx.sso.utils.base_migrator.settings')
    def test_get_social_team_map_with_authenticator_specific_setting(self, mock_settings):
        """Test get_social_team_map returns authenticator-specific setting when available."""
        # Set up mock settings
        authenticator_map = {'team1': {'organization': 'org1'}}
        global_map = {'global_team': {'organization': 'global_org'}}

        # Mock getattr to return the specific setting
        with patch('awx.sso.utils.base_migrator.getattr') as mock_getattr:
            mock_getattr.side_effect = lambda obj, name, default=None: {
                'SOCIAL_AUTH_GITHUB_TEAM_MAP': authenticator_map,
                'SOCIAL_AUTH_TEAM_MAP': global_map,
            }.get(name, default)

            result = self.migrator.get_social_team_map('SOCIAL_AUTH_GITHUB_TEAM_MAP')

            assert result == authenticator_map
            # Verify it was called with the authenticator-specific setting first
            mock_getattr.assert_any_call(mock_settings, 'SOCIAL_AUTH_GITHUB_TEAM_MAP', None)

    @patch('awx.sso.utils.base_migrator.settings')
    def test_get_social_team_map_fallback_to_global(self, mock_settings):
        """Test get_social_team_map falls back to global setting when authenticator-specific is empty."""
        # Set up mock settings
        global_map = {'global_team': {'organization': 'global_org'}}

        # Mock getattr to return None for authenticator-specific, global for fallback
        with patch('awx.sso.utils.base_migrator.getattr') as mock_getattr:
            mock_getattr.side_effect = lambda obj, name, default=None: {'SOCIAL_AUTH_GITHUB_TEAM_MAP': None, 'SOCIAL_AUTH_TEAM_MAP': global_map}.get(
                name, default
            )

            result = self.migrator.get_social_team_map('SOCIAL_AUTH_GITHUB_TEAM_MAP')

            assert result == global_map
            # Verify both calls were made
            mock_getattr.assert_any_call(mock_settings, 'SOCIAL_AUTH_GITHUB_TEAM_MAP', None)
            mock_getattr.assert_any_call(mock_settings, 'SOCIAL_AUTH_TEAM_MAP', {})

    @patch('awx.sso.utils.base_migrator.settings')
    def test_get_social_team_map_empty_dict_fallback(self, mock_settings):
        """Test get_social_team_map returns empty dict when neither setting exists."""
        # Mock getattr to return None for both settings
        with patch('awx.sso.utils.base_migrator.getattr') as mock_getattr:
            mock_getattr.side_effect = lambda obj, name, default=None: {'SOCIAL_AUTH_GITHUB_TEAM_MAP': None, 'SOCIAL_AUTH_TEAM_MAP': {}}.get(name, default)

            result = self.migrator.get_social_team_map('SOCIAL_AUTH_GITHUB_TEAM_MAP')

            assert result == {}

    @patch('awx.sso.utils.base_migrator.settings')
    def test_get_social_org_map_with_empty_string_fallback(self, mock_settings):
        """Test get_social_org_map falls back to global when authenticator-specific is empty string."""
        # Set up mock settings
        global_map = {'global_org': ['global_team']}

        # Mock getattr to return empty string for authenticator-specific
        with patch('awx.sso.utils.base_migrator.getattr') as mock_getattr:
            mock_getattr.side_effect = lambda obj, name, default=None: {
                'SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP': '',
                'SOCIAL_AUTH_ORGANIZATION_MAP': global_map,
            }.get(name, default)

            result = self.migrator.get_social_org_map('SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP')

            assert result == global_map

    @patch('awx.sso.utils.base_migrator.settings')
    def test_get_social_team_map_with_empty_dict_fallback(self, mock_settings):
        """Test get_social_team_map falls back to global when authenticator-specific is empty dict."""
        # Set up mock settings
        global_map = {'global_team': {'organization': 'global_org'}}

        # Mock getattr to return empty dict for authenticator-specific
        with patch('awx.sso.utils.base_migrator.getattr') as mock_getattr:
            mock_getattr.side_effect = lambda obj, name, default=None: {'SOCIAL_AUTH_GITHUB_TEAM_MAP': {}, 'SOCIAL_AUTH_TEAM_MAP': global_map}.get(
                name, default
            )

            result = self.migrator.get_social_team_map('SOCIAL_AUTH_GITHUB_TEAM_MAP')

            # Empty dict is falsy, so it should fall back to global
            assert result == global_map

    def test_get_social_org_map_different_authenticators(self):
        """Test get_social_org_map works with different authenticator setting names."""
        test_cases = [
            'SOCIAL_AUTH_GITHUB_ORGANIZATION_MAP',
            'SOCIAL_AUTH_AZUREAD_OAUTH2_ORGANIZATION_MAP',
            'SOCIAL_AUTH_SAML_ORGANIZATION_MAP',
            'SOCIAL_AUTH_OIDC_ORGANIZATION_MAP',
        ]

        for setting_name in test_cases:
            with patch('awx.sso.utils.base_migrator.getattr') as mock_getattr:
                mock_getattr.side_effect = lambda obj, name, default=None: {
                    setting_name: {'test_org': ['test_team']},
                    'SOCIAL_AUTH_ORGANIZATION_MAP': {'fallback_org': ['fallback_team']},
                }.get(name, default)

                result = self.migrator.get_social_org_map(setting_name)

                assert result == {'test_org': ['test_team']}

    def test_get_social_team_map_different_authenticators(self):
        """Test get_social_team_map works with different authenticator setting names."""
        test_cases = ['SOCIAL_AUTH_GITHUB_TEAM_MAP', 'SOCIAL_AUTH_AZUREAD_OAUTH2_TEAM_MAP', 'SOCIAL_AUTH_SAML_TEAM_MAP', 'SOCIAL_AUTH_OIDC_TEAM_MAP']

        for setting_name in test_cases:
            with patch('awx.sso.utils.base_migrator.getattr') as mock_getattr:
                mock_getattr.side_effect = lambda obj, name, default=None: {
                    setting_name: {'test_team': {'organization': 'test_org'}},
                    'SOCIAL_AUTH_TEAM_MAP': {'fallback_team': {'organization': 'fallback_org'}},
                }.get(name, default)

                result = self.migrator.get_social_team_map(setting_name)

                assert result == {'test_team': {'organization': 'test_org'}}


class TestHandleLoginOverride:
    """Tests for handle_login_override method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.gateway_client = Mock()
        self.command = Mock()
        self.migrator = BaseAuthenticatorMigrator(self.gateway_client, self.command)

        # Reset the class-level flag before each test
        BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator = False

    def test_handle_login_override_no_login_redirect_override(self):
        """Test that method returns early when no login_redirect_override is provided."""
        config = {}
        valid_login_urls = ['/sso/login/github']

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should not call any gateway client methods
        self.gateway_client.get_base_url.assert_not_called()
        self.gateway_client.update_gateway_setting.assert_not_called()
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is False

    def test_handle_login_override_empty_login_redirect_override(self):
        """Test that method returns early when login_redirect_override is empty."""
        config = {'login_redirect_override': ''}
        valid_login_urls = ['/sso/login/github']

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should not call any gateway client methods
        self.gateway_client.get_base_url.assert_not_called()
        self.gateway_client.update_gateway_setting.assert_not_called()
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is False

    def test_handle_login_override_no_url_match(self):
        """Test that method returns early when login_redirect_override doesn't match valid URLs."""
        config = {'login_redirect_override': 'https://localhost:3000/sso/login/saml'}
        valid_login_urls = ['/sso/login/github', '/sso/login/azuread-oauth2']

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should not call any gateway client methods
        self.gateway_client.get_base_url.assert_not_called()
        self.gateway_client.update_gateway_setting.assert_not_called()
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is False

    def test_handle_login_override_no_gateway_authenticator(self):
        """Test that method returns early when gateway_authenticator is missing."""
        config = {'login_redirect_override': 'https://localhost:3000/sso/login/github'}
        valid_login_urls = ['/sso/login/github']

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should not call any gateway client methods
        self.gateway_client.get_base_url.assert_not_called()
        self.gateway_client.update_gateway_setting.assert_not_called()
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is False

    def test_handle_login_override_empty_gateway_authenticator(self):
        """Test that method returns early when gateway_authenticator is empty."""
        config = {'login_redirect_override': 'https://localhost:3000/sso/login/github', 'gateway_authenticator': {}}
        valid_login_urls = ['/sso/login/github']

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should not call any gateway client methods
        self.gateway_client.get_base_url.assert_not_called()
        self.gateway_client.update_gateway_setting.assert_not_called()
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is False

    def test_handle_login_override_no_sso_login_url(self):
        """Test that method returns early when sso_login_url is missing."""
        config = {'login_redirect_override': 'https://localhost:3000/sso/login/github', 'gateway_authenticator': {'id': 123}}
        valid_login_urls = ['/sso/login/github']

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should not call any gateway client methods
        self.gateway_client.get_base_url.assert_not_called()
        self.gateway_client.update_gateway_setting.assert_not_called()
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is False

    def test_handle_login_override_empty_sso_login_url(self):
        """Test that method returns early when sso_login_url is empty."""
        config = {'login_redirect_override': 'https://localhost:3000/sso/login/github', 'gateway_authenticator': {'id': 123, 'sso_login_url': ''}}
        valid_login_urls = ['/sso/login/github']

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should not call any gateway client methods
        self.gateway_client.get_base_url.assert_not_called()
        self.gateway_client.update_gateway_setting.assert_not_called()
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is False

    def test_handle_login_override_successful_update(self):
        """Test successful LOGIN_REDIRECT_OVERRIDE update."""
        config = {
            'login_redirect_override': 'https://localhost:3000/sso/login/github',
            'gateway_authenticator': {'id': 123, 'sso_login_url': '/sso/auth/login/123/'},
        }
        valid_login_urls = ['/sso/login/github']

        # Mock gateway client methods
        self.gateway_client.get_base_url.return_value = 'https://gateway.example.com'
        self.migrator.handle_login_override(config, valid_login_urls)

        # Verify gateway client methods were called correctly
        self.gateway_client.get_base_url.assert_called_once()
        self.gateway_client.update_gateway_setting.assert_called_once_with('LOGIN_REDIRECT_OVERRIDE', 'https://gateway.example.com/sso/auth/login/123/')
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is True

    def test_handle_login_override_multiple_valid_urls_first_matches(self):
        """Test that first matching URL in valid_login_urls is used."""
        config = {
            'login_redirect_override': 'https://localhost:3000/sso/login/github-org',
            'gateway_authenticator': {'id': 123, 'sso_login_url': '/sso/auth/login/123/'},
        }
        valid_login_urls = ['/sso/login/github-org', '/sso/login/github-team', '/sso/login/github']

        # Mock gateway client methods
        self.gateway_client.get_base_url.return_value = 'https://gateway.example.com'

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should still work since first URL matches
        self.gateway_client.update_gateway_setting.assert_called_once_with('LOGIN_REDIRECT_OVERRIDE', 'https://gateway.example.com/sso/auth/login/123/')
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is True

    def test_handle_login_override_multiple_valid_urls_last_matches(self):
        """Test that last matching URL in valid_login_urls is used."""
        config = {
            'login_redirect_override': 'https://localhost:3000/sso/login/github',
            'gateway_authenticator': {'id': 123, 'sso_login_url': '/sso/auth/login/123/'},
        }
        valid_login_urls = ['/sso/login/github-org', '/sso/login/github-team', '/sso/login/github']

        # Mock gateway client methods
        self.gateway_client.get_base_url.return_value = 'https://gateway.example.com'

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should work since last URL matches
        self.gateway_client.update_gateway_setting.assert_called_once_with('LOGIN_REDIRECT_OVERRIDE', 'https://gateway.example.com/sso/auth/login/123/')
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is True

    def test_handle_login_override_partial_url_match(self):
        """Test that partial URL matching works (using 'in' operator)."""
        config = {
            'login_redirect_override': 'https://controller.example.com/sso/login/azuread-oauth2/?next=%2Fdashboard',
            'gateway_authenticator': {'id': 456, 'sso_login_url': '/auth/login/azuread/456/'},
        }
        valid_login_urls = ['/sso/login/azuread-oauth2']

        # Mock gateway client methods
        self.gateway_client.get_base_url.return_value = 'https://gateway.example.com:8080'
        self.migrator.handle_login_override(config, valid_login_urls)

        # Should work since valid URL is contained in login_redirect_override
        self.gateway_client.update_gateway_setting.assert_called_once_with(
            'LOGIN_REDIRECT_OVERRIDE', 'https://gateway.example.com:8080/auth/login/azuread/456/?next=%2Fdashboard'
        )
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is True

    def test_handle_login_override_saml_with_parameters(self):
        """Test LOGIN_REDIRECT_OVERRIDE with SAML IDP parameters."""
        config = {
            'login_redirect_override': 'https://localhost:3000/sso/login/saml/?idp=mycompany',
            'gateway_authenticator': {'id': 789, 'sso_login_url': '/auth/login/saml/789/'},
        }
        valid_login_urls = ['/sso/login/saml/?idp=mycompany']

        # Mock gateway client methods
        self.gateway_client.get_base_url.return_value = 'https://gateway.local'

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should work with SAML parameter URLs
        self.gateway_client.update_gateway_setting.assert_called_once_with(
            'LOGIN_REDIRECT_OVERRIDE', 'https://gateway.local/auth/login/saml/789/?idp=mycompany'
        )
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is True

    def test_handle_login_override_github_with_trailing_slash(self):
        """Test LOGIN_REDIRECT_OVERRIDE with trailing slash."""
        config = {
            'login_redirect_override': 'https://localhost:3000/sso/login/github-enterprise/',
            'gateway_authenticator': {'id': 999, 'sso_login_url': '/auth/login/github/999/'},
        }
        valid_login_urls = ['/sso/login/github-enterprise', '/sso/login/github-enterprise/']

        # Mock gateway client methods
        self.gateway_client.get_base_url.return_value = 'https://gateway.internal'

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should work with trailing slash URLs
        self.gateway_client.update_gateway_setting.assert_called_once_with('LOGIN_REDIRECT_OVERRIDE', 'https://gateway.internal/auth/login/github/999/')
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is True

    def test_handle_login_override_empty_valid_urls_list(self):
        """Test that method returns early when valid_login_urls is empty."""
        config = {
            'login_redirect_override': 'https://localhost:3000/sso/login/github',
            'gateway_authenticator': {'id': 123, 'sso_login_url': '/sso/auth/login/123/'},
        }
        valid_login_urls = []

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should not call any gateway client methods
        self.gateway_client.get_base_url.assert_not_called()
        self.gateway_client.update_gateway_setting.assert_not_called()
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is False

    def test_handle_login_override_preserves_existing_flag_state(self):
        """Test that method preserves flag state if it was already set."""
        # Set flag to True initially
        BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator = True

        config = {
            'login_redirect_override': 'https://localhost:3000/sso/login/github',
            'gateway_authenticator': {'id': 123, 'sso_login_url': '/sso/auth/login/123/'},
        }
        valid_login_urls = ['/sso/login/github']

        # Mock gateway client methods
        self.gateway_client.get_base_url.return_value = 'https://gateway.example.com'

        self.migrator.handle_login_override(config, valid_login_urls)

        # Flag should still be True
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is True

    def test_handle_login_override_writes_output_message(self):
        """Test that method writes output message when updating."""
        config = {
            'login_redirect_override': 'https://localhost:3000/sso/login/google-oauth2',
            'gateway_authenticator': {'id': 555, 'sso_login_url': '/auth/login/google/555/'},
        }
        valid_login_urls = ['/sso/login/google-oauth2']

        # Mock gateway client methods
        self.gateway_client.get_base_url.return_value = 'https://gateway.test'

        # Mock _write_output method
        with patch.object(self.migrator, '_write_output') as mock_write_output:
            self.migrator.handle_login_override(config, valid_login_urls)

            # Verify output message was written
            mock_write_output.assert_called_once_with('Updating LOGIN_REDIRECT_OVERRIDE to: https://gateway.test/auth/login/google/555/')

    @pytest.mark.parametrize(
        "login_redirect_override,valid_urls,expected_match",
        [
            # Test Azure AD variations
            ('https://localhost:3000/sso/login/azuread-oauth2', ['/sso/login/azuread-oauth2'], True),
            ('https://localhost:3000/sso/login/azuread-oauth2/', ['/sso/login/azuread-oauth2'], True),
            ('https://controller.example.com/sso/login/azuread-oauth2?next=/home', ['/sso/login/azuread-oauth2'], True),
            # Test Google OAuth2 variations
            ('https://localhost:3000/sso/login/google-oauth2', ['/sso/login/google-oauth2'], True),
            ('https://localhost:3000/sso/login/google-oauth2/', ['/sso/login/google-oauth2'], True),
            # Test GitHub variations
            ('https://localhost:3000/sso/login/github', ['/sso/login/github'], True),
            ('https://localhost:3000/sso/login/github-org', ['/sso/login/github-org'], True),
            ('https://localhost:3000/sso/login/github-team', ['/sso/login/github-team'], True),
            ('https://localhost:3000/sso/login/github-enterprise', ['/sso/login/github-enterprise'], True),
            # Test SAML variations
            ('https://localhost:3000/sso/login/saml/?idp=company', ['/sso/login/saml/?idp=company'], True),
            ('https://localhost:3000/sso/login/saml/?idp=test-org', ['/sso/login/saml/?idp=test-org'], True),
            # Test non-matching cases
            ('https://localhost:3000/sso/login/ldap', ['/sso/login/github'], False),
            ('https://localhost:3000/sso/login/azuread-oauth2', ['/sso/login/google-oauth2'], False),
            ('https://localhost:3000/sso/login/saml/?idp=wrong', ['/sso/login/saml/?idp=company'], False),
            # Test multiple valid URLs
            ('https://localhost:3000/sso/login/github-org', ['/sso/login/github', '/sso/login/github-org'], True),
            ('https://localhost:3000/sso/login/github', ['/sso/login/github-org', '/sso/login/github'], True),
            # Test improved URL parsing scenarios - better boundary detection
            ('https://localhost:3000/sso/login/github-enterprise', ['/sso/login/github'], False),  # Should NOT match due to better parsing
            ('https://localhost:3000/sso/login/saml/?idp=company&next=/home', ['/sso/login/saml/?idp=company'], True),
            ('https://localhost:3000/sso/login/saml/?idp=company', ['/sso/login/saml/?idp=different'], False),
            ('https://controller.example.com:8080/sso/login/azuread-oauth2/?next=/dashboard', ['/sso/login/azuread-oauth2'], True),
            ('http://localhost/sso/login/github?state=abc123', ['/sso/login/github'], True),
            # Test boundary detection edge cases
            ('https://localhost:3000/sso/login/github/', ['/sso/login/github'], True),  # Trailing slash should match
            ('https://localhost:3000/sso/login/github#section', ['/sso/login/github'], True),  # Fragment should match
        ],
    )
    def test_handle_login_override_url_matching_variations(self, login_redirect_override, valid_urls, expected_match):
        """Test various URL matching scenarios parametrically."""
        config = {'login_redirect_override': login_redirect_override, 'gateway_authenticator': {'id': 123, 'sso_login_url': '/auth/login/test/123/'}}

        # Mock gateway client methods
        self.gateway_client.get_base_url.return_value = 'https://gateway.test'

        self.migrator.handle_login_override(config, valid_urls)

        if expected_match:
            # Should call gateway methods when URL matches
            self.gateway_client.get_base_url.assert_called_once()
            self.gateway_client.update_gateway_setting.assert_called_once()
            assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is True
        else:
            # Should not call gateway methods when URL doesn't match
            self.gateway_client.get_base_url.assert_not_called()
            self.gateway_client.update_gateway_setting.assert_not_called()
            assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is False

    def test_handle_login_override_improved_url_parsing(self):
        """Test that improved URL parsing with proper path boundary detection prevents false positive matches."""
        # This test demonstrates the improvement over simple string matching
        config = {
            'login_redirect_override': 'https://localhost:3000/sso/login/github-enterprise',
            'gateway_authenticator': {'id': 123, 'sso_login_url': '/auth/login/test/123/'},
        }

        # With the old simple string matching, this would incorrectly match
        # because '/sso/login/github' is contained in '/sso/login/github-enterprise'
        # But with proper URL parsing, it should NOT match
        valid_login_urls = ['/sso/login/github']

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should NOT match due to improved parsing
        self.gateway_client.get_base_url.assert_not_called()
        self.gateway_client.update_gateway_setting.assert_not_called()
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is False

    def test_handle_login_override_query_parameter_handling(self):
        """Test that query parameters are properly handled in URL matching."""
        config = {
            'login_redirect_override': 'https://localhost:3000/sso/login/saml/?idp=mycompany&next=%2Fdashboard',
            'gateway_authenticator': {'id': 456, 'sso_login_url': '/auth/login/saml/456/?idp=IdP'},
        }

        # Should match the SAML URL with the correct IDP parameter (boundary-aware matching)
        valid_login_urls = ['/sso/login/saml/?idp=mycompany']

        self.gateway_client.get_base_url.return_value = 'https://gateway.test'

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should match because the query parameter is properly contained with boundaries
        self.gateway_client.get_base_url.assert_called_once()
        self.gateway_client.update_gateway_setting.assert_called_once_with(
            'LOGIN_REDIRECT_OVERRIDE', 'https://gateway.test/auth/login/saml/456/?idp=IdP&next=%2Fdashboard'
        )
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is True

    def test_handle_login_override_different_query_parameters(self):
        """Test that different query parameters don't match."""
        config = {
            'login_redirect_override': 'https://localhost:3000/sso/login/saml/?idp=company-a',
            'gateway_authenticator': {'id': 456, 'sso_login_url': '/auth/login/saml/456/'},
        }

        # Should NOT match SAML URL with different IDP parameter
        valid_login_urls = ['/sso/login/saml/?idp=company-b']

        self.migrator.handle_login_override(config, valid_login_urls)

        # Should NOT match because the query parameters are different
        self.gateway_client.get_base_url.assert_not_called()
        self.gateway_client.update_gateway_setting.assert_not_called()
        assert BaseAuthenticatorMigrator.login_redirect_override_set_by_migrator is False
