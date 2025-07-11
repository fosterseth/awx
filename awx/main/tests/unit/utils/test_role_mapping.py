"""
Unit tests for role mapping utilities.
"""

import pytest
from awx.main.utils.gateway_mapping import role_map_to_gateway_format
from awx.sso.utils.ldap_migrator import LDAPMigrator


def get_role_mappers(role_map, start_order=1):
    """Helper function to get just the mappers from role_map_to_gateway_format."""
    result, _ = role_map_to_gateway_format(role_map, start_order)
    return result


def ldap_group_allow_to_gateway_format(result, ldap_group, deny=False, start_order=1):
    """Helper function to test LDAP group allow mapping via LDAPMigrator."""
    migrator = LDAPMigrator()
    return migrator._ldap_group_allow_to_gateway_format(result, ldap_group, deny, start_order)


class TestRoleMapToGatewayFormat:
    """Tests for role_map_to_gateway_format function."""

    def test_none_input(self):
        """Test that None input returns empty list."""
        result, next_order = role_map_to_gateway_format(None)
        assert result == []
        assert next_order == 1  # Default start_order

    def test_empty_dict(self):
        """Test that empty dict returns empty list."""
        result, next_order = role_map_to_gateway_format({})
        assert result == []
        assert next_order == 1

    def test_is_superuser_single_group(self):
        """Test is_superuser with single group."""
        role_map = {"is_superuser": "cn=awx_super_users,OU=administration groups,DC=contoso,DC=com"}

        result, _ = role_map_to_gateway_format(role_map)

        expected = [
            {
                "name": "is_superuser - role",
                "authenticator": -1,
                "revoke": True,
                "map_type": "is_superuser",
                "team": None,
                "organization": None,
                "triggers": {
                    "groups": {
                        "has_or": ["cn=awx_super_users,OU=administration groups,DC=contoso,DC=com"],
                    }
                },
                "order": 1,
            }
        ]

        assert result == expected

    def test_is_superuser_multiple_groups(self):
        """Test is_superuser with multiple groups."""
        role_map = {"is_superuser": ["cn=super_users,dc=example,dc=com", "cn=admins,dc=example,dc=com"]}

        result, _ = role_map_to_gateway_format(role_map)

        expected = [
            {
                "name": "is_superuser - role",
                "authenticator": -1,
                "revoke": True,
                "map_type": "is_superuser",
                "team": None,
                "organization": None,
                "triggers": {
                    "groups": {
                        "has_or": ["cn=super_users,dc=example,dc=com", "cn=admins,dc=example,dc=com"],
                    }
                },
                "order": 1,
            }
        ]

        assert result == expected

    def test_is_system_auditor_single_group(self):
        """Test is_system_auditor with single group."""
        role_map = {"is_system_auditor": "cn=auditors,dc=example,dc=com"}

        result, _ = role_map_to_gateway_format(role_map)

        expected = [
            {
                "name": "is_system_auditor - role",
                "authenticator": -1,
                "revoke": True,
                "map_type": "role",
                "role": "Platform Auditor",
                "team": None,
                "organization": None,
                "triggers": {
                    "groups": {
                        "has_or": ["cn=auditors,dc=example,dc=com"],
                    }
                },
                "order": 1,
            }
        ]

        assert result == expected

    def test_is_system_auditor_multiple_groups(self):
        """Test is_system_auditor with multiple groups."""
        role_map = {"is_system_auditor": ["cn=auditors,dc=example,dc=com", "cn=viewers,dc=example,dc=com"]}

        result, _ = role_map_to_gateway_format(role_map)

        expected = [
            {
                "name": "is_system_auditor - role",
                "authenticator": -1,
                "revoke": True,
                "map_type": "role",
                "role": "Platform Auditor",
                "team": None,
                "organization": None,
                "triggers": {
                    "groups": {
                        "has_or": ["cn=auditors,dc=example,dc=com", "cn=viewers,dc=example,dc=com"],
                    }
                },
                "order": 1,
            }
        ]

        assert result == expected

    def test_multiple_roles(self):
        """Test multiple role mappings."""
        role_map = {"is_superuser": "cn=super_users,dc=example,dc=com", "is_system_auditor": "cn=auditors,dc=example,dc=com"}

        result, _ = role_map_to_gateway_format(role_map)

        expected = [
            {
                "name": "is_superuser - role",
                "authenticator": -1,
                "revoke": True,
                "map_type": "is_superuser",
                "team": None,
                "organization": None,
                "triggers": {
                    "groups": {
                        "has_or": ["cn=super_users,dc=example,dc=com"],
                    }
                },
                "order": 1,
            },
            {
                "name": "is_system_auditor - role",
                "authenticator": -1,
                "revoke": True,
                "map_type": "role",
                "role": "Platform Auditor",
                "team": None,
                "organization": None,
                "triggers": {
                    "groups": {
                        "has_or": ["cn=auditors,dc=example,dc=com"],
                    }
                },
                "order": 2,
            },
        ]

        assert result == expected

    def test_unsupported_role_flag(self):
        """Test that unsupported role flags are ignored."""
        role_map = {
            "is_superuser": "cn=super_users,dc=example,dc=com",
            "is_staff": "cn=staff,dc=example,dc=com",  # Unsupported flag
            "is_system_auditor": "cn=auditors,dc=example,dc=com",
        }

        result, _ = role_map_to_gateway_format(role_map)

        # Should only have 2 mappers (is_superuser and is_system_auditor)
        assert len(result) == 2
        assert result[0]["map_type"] == "is_superuser"
        assert result[1]["map_type"] == "role"
        assert result[1]["role"] == "Platform Auditor"

    def test_order_increments_correctly(self):
        """Test that order values increment correctly."""
        role_map = {"is_superuser": "cn=super_users,dc=example,dc=com", "is_system_auditor": "cn=auditors,dc=example,dc=com"}

        result, _ = role_map_to_gateway_format(role_map)

        assert len(result) == 2
        assert result[0]["order"] == 1
        assert result[1]["order"] == 2

    def test_start_order_parameter(self):
        """Test that start_order parameter is respected."""
        role_map = {"is_superuser": "cn=super_users,dc=example,dc=com"}

        result, next_order = role_map_to_gateway_format(role_map, start_order=5)

        assert result[0]["order"] == 5
        assert next_order == 6

    def test_string_to_list_conversion(self):
        """Test that string groups are converted to lists."""
        role_map = {"is_superuser": "single-group"}

        result, _ = role_map_to_gateway_format(role_map)

        # Should convert string to list for has_or
        assert result[0]["triggers"]["groups"]["has_or"] == ["single-group"]

    def test_triggers_format_validation(self):
        """Test that trigger formats match Gateway specification."""
        role_map = {"is_superuser": ["group1", "group2"]}

        result, _ = role_map_to_gateway_format(role_map)

        # Validate that triggers follow Gateway format
        triggers = result[0]["triggers"]
        assert "groups" in triggers
        assert "has_or" in triggers["groups"]
        assert isinstance(triggers["groups"]["has_or"], list)
        assert triggers["groups"]["has_or"] == ["group1", "group2"]

    def test_ldap_dn_format(self):
        """Test with realistic LDAP DN format."""
        role_map = {
            "is_superuser": "cn=awx_super_users,OU=administration groups,DC=contoso,DC=com",
            "is_system_auditor": "cn=awx_auditors,OU=administration groups,DC=contoso,DC=com",
        }

        result, _ = role_map_to_gateway_format(role_map)

        assert len(result) == 2
        assert result[0]["triggers"]["groups"]["has_or"] == ["cn=awx_super_users,OU=administration groups,DC=contoso,DC=com"]
        assert result[1]["triggers"]["groups"]["has_or"] == ["cn=awx_auditors,OU=administration groups,DC=contoso,DC=com"]

    def test_gateway_format_compliance(self):
        """Test that all results comply with Gateway role mapping format."""
        role_map = {"is_superuser": "cn=super_users,dc=example,dc=com", "is_system_auditor": "cn=auditors,dc=example,dc=com"}

        result, _ = role_map_to_gateway_format(role_map)

        for mapping in result:
            # Required fields per Gateway spec
            assert "name" in mapping
            assert "authenticator" in mapping
            assert "map_type" in mapping
            assert "organization" in mapping
            assert "team" in mapping
            assert "triggers" in mapping
            assert "order" in mapping
            assert "revoke" in mapping

            # Field types
            assert isinstance(mapping["name"], str)
            assert isinstance(mapping["authenticator"], int)
            assert mapping["map_type"] in ["is_superuser", "role"]
            assert mapping["organization"] is None
            assert mapping["team"] is None
            assert isinstance(mapping["triggers"], dict)
            assert isinstance(mapping["order"], int)
            assert isinstance(mapping["revoke"], bool)

            # Specific field validations based on map_type
            if mapping["map_type"] == "is_superuser":
                assert "role" not in mapping
            elif mapping["map_type"] == "role":
                assert "role" in mapping
                assert isinstance(mapping["role"], str)
                assert mapping["role"] == "Platform Auditor"


# Parametrized tests for role mappings
@pytest.mark.parametrize(
    "role_map,expected_length",
    [
        (None, 0),
        ({}, 0),
        ({"is_superuser": "group1"}, 1),
        ({"is_system_auditor": "group1"}, 1),
        ({"is_superuser": "group1", "is_system_auditor": "group2"}, 2),
        ({"is_staff": "group1"}, 0),  # Unsupported flag
        ({"is_superuser": "group1", "is_staff": "group2", "is_system_auditor": "group3"}, 2),  # Mixed supported/unsupported
    ],
)
def test_role_map_result_lengths(role_map, expected_length):
    """Test that role_map_to_gateway_format returns expected number of mappings."""
    result, _ = role_map_to_gateway_format(role_map)
    assert len(result) == expected_length


# Edge case tests
def test_empty_groups_handling():
    """Test handling of empty group lists."""
    role_map = {"is_superuser": []}

    result, _ = role_map_to_gateway_format(role_map)

    assert len(result) == 1
    assert result[0]["triggers"]["groups"]["has_or"] == []


def test_mixed_group_types():
    """Test handling of mixed group types (string and list)."""
    role_map = {"is_superuser": "single-group", "is_system_auditor": ["group1", "group2"]}

    result, _ = role_map_to_gateway_format(role_map)

    assert len(result) == 2
    assert result[0]["triggers"]["groups"]["has_or"] == ["single-group"]
    assert result[1]["triggers"]["groups"]["has_or"] == ["group1", "group2"]


def test_realistic_ldap_user_flags_by_group():
    """Test with realistic LDAP USER_FLAGS_BY_GROUP data."""
    role_map = {"is_superuser": "cn=awx_super_users,OU=administration groups,DC=contoso,DC=com"}

    result, _ = role_map_to_gateway_format(role_map)

    # This is exactly the use case from the user's example
    assert len(result) == 1
    assert result[0]["map_type"] == "is_superuser"
    assert result[0]["triggers"]["groups"]["has_or"] == ["cn=awx_super_users,OU=administration groups,DC=contoso,DC=com"]
    assert result[0]["revoke"] is True
    assert result[0]["team"] is None
    assert result[0]["organization"] is None


class TestLdapGroupAllowToGatewayFormat:
    """Tests for ldap_group_allow_to_gateway_format function."""

    def test_none_input_with_empty_result(self):
        """Test that None input with empty result returns unchanged result."""
        result = []
        output_result, next_order = ldap_group_allow_to_gateway_format(result, None, deny=False)

        assert output_result == []
        assert next_order == 1  # Default start_order

    def test_none_input_with_existing_result(self):
        """Test that None input with existing mappers returns unchanged result."""
        result = [{"existing": "mapper"}]
        output_result, next_order = ldap_group_allow_to_gateway_format(result, None, deny=False, start_order=5)

        assert output_result == [{"existing": "mapper"}]
        assert next_order == 5  # start_order unchanged

    def test_require_group_mapping(self):
        """Test LDAP REQUIRE_GROUP mapping (deny=False)."""
        result = []
        ldap_group = "cn=allowed_users,dc=example,dc=com"

        output_result, next_order = ldap_group_allow_to_gateway_format(result, ldap_group, deny=False, start_order=1)

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

    def test_deny_group_mapping(self):
        """Test LDAP DENY_GROUP mapping (deny=True)."""
        result = []
        ldap_group = "cn=blocked_users,dc=example,dc=com"

        output_result, next_order = ldap_group_allow_to_gateway_format(result, ldap_group, deny=True, start_order=1)

        expected = [
            {
                "name": "LDAP-DenyGroup",
                "authenticator": -1,
                "map_type": "allow",
                "revoke": True,
                "triggers": {"groups": {"has_or": ["cn=blocked_users,dc=example,dc=com"]}},
                "order": 1,
            }
        ]

        assert output_result == expected
        assert next_order == 2

    def test_appending_to_existing_result(self):
        """Test appending to existing result list."""
        existing_mapper = {
            "name": "existing-mapper",
            "authenticator": -1,
            "map_type": "role",
            "order": 1,
        }
        result = [existing_mapper]
        ldap_group = "cn=new_group,dc=example,dc=com"

        output_result, next_order = ldap_group_allow_to_gateway_format(result, ldap_group, deny=False, start_order=2)

        assert len(output_result) == 2
        assert output_result[0] == existing_mapper  # Original mapper unchanged
        assert output_result[1]["name"] == "LDAP-RequireGroup"
        assert output_result[1]["order"] == 2
        assert next_order == 3

    def test_custom_start_order(self):
        """Test that custom start_order is respected."""
        result = []
        ldap_group = "cn=test_group,dc=example,dc=com"

        output_result, next_order = ldap_group_allow_to_gateway_format(result, ldap_group, deny=False, start_order=10)

        assert output_result[0]["order"] == 10
        assert next_order == 11

    def test_require_vs_deny_trigger_differences(self):
        """Test the difference between require and deny group triggers."""
        ldap_group = "cn=test_group,dc=example,dc=com"

        # Test require group (deny=False)
        require_result, _ = ldap_group_allow_to_gateway_format([], ldap_group, deny=False)

        # Test deny group (deny=True)
        deny_result, _ = ldap_group_allow_to_gateway_format([], ldap_group, deny=True)

        # Require group should use has_and
        assert require_result[0]["triggers"]["groups"]["has_and"] == ["cn=test_group,dc=example,dc=com"]
        assert require_result[0]["revoke"] is False
        assert require_result[0]["name"] == "LDAP-RequireGroup"

        # Deny group should use has_or
        assert deny_result[0]["triggers"]["groups"]["has_or"] == ["cn=test_group,dc=example,dc=com"]
        assert deny_result[0]["revoke"] is True
        assert deny_result[0]["name"] == "LDAP-DenyGroup"

    def test_realistic_ldap_dn_format(self):
        """Test with realistic LDAP DN format."""
        result = []

        # Test with require group
        require_group = "cn=awx_users,OU=application groups,DC=contoso,DC=com"
        output_result, next_order = ldap_group_allow_to_gateway_format(result, require_group, deny=False, start_order=1)

        assert len(output_result) == 1
        assert output_result[0]["triggers"]["groups"]["has_and"] == ["cn=awx_users,OU=application groups,DC=contoso,DC=com"]
        assert output_result[0]["name"] == "LDAP-RequireGroup"
        assert next_order == 2

    def test_multiple_sequential_calls(self):
        """Test multiple sequential calls to build complex allow mappers."""
        result = []

        # Add deny group first
        result, next_order = ldap_group_allow_to_gateway_format(result, "cn=blocked,dc=example,dc=com", deny=True, start_order=1)

        # Add require group second
        result, next_order = ldap_group_allow_to_gateway_format(result, "cn=allowed,dc=example,dc=com", deny=False, start_order=next_order)

        assert len(result) == 2

        # First mapper should be deny group
        assert result[0]["name"] == "LDAP-DenyGroup"
        assert result[0]["revoke"] is True
        assert result[0]["triggers"]["groups"]["has_or"] == ["cn=blocked,dc=example,dc=com"]
        assert result[0]["order"] == 1

        # Second mapper should be require group
        assert result[1]["name"] == "LDAP-RequireGroup"
        assert result[1]["revoke"] is False
        assert result[1]["triggers"]["groups"]["has_and"] == ["cn=allowed,dc=example,dc=com"]
        assert result[1]["order"] == 2

        assert next_order == 3

    def test_gateway_format_compliance(self):
        """Test that all results comply with Gateway allow mapping format."""
        result = []

        # Test both deny and require groups
        result, _ = ldap_group_allow_to_gateway_format(result, "cn=denied,dc=example,dc=com", deny=True, start_order=1)
        result, _ = ldap_group_allow_to_gateway_format(result, "cn=required,dc=example,dc=com", deny=False, start_order=2)

        for mapping in result:
            # Required fields per Gateway spec
            assert "name" in mapping
            assert "authenticator" in mapping
            assert "map_type" in mapping
            assert "triggers" in mapping
            assert "order" in mapping
            assert "revoke" in mapping

            # Field types
            assert isinstance(mapping["name"], str)
            assert isinstance(mapping["authenticator"], int)
            assert mapping["map_type"] == "allow"
            assert isinstance(mapping["triggers"], dict)
            assert isinstance(mapping["order"], int)
            assert isinstance(mapping["revoke"], bool)

            # Trigger format validation
            assert "groups" in mapping["triggers"]
            groups_trigger = mapping["triggers"]["groups"]

            # Should have either has_and or has_or, but not both
            has_and = "has_and" in groups_trigger
            has_or = "has_or" in groups_trigger
            assert has_and != has_or  # XOR - exactly one should be true

            if has_and:
                assert isinstance(groups_trigger["has_and"], list)
                assert len(groups_trigger["has_and"]) == 1
            if has_or:
                assert isinstance(groups_trigger["has_or"], list)
                assert len(groups_trigger["has_or"]) == 1

    def test_original_result_not_modified_when_none(self):
        """Test that original result list is not modified when ldap_group is None."""
        original_result = [{"original": "mapper"}]
        result_copy = original_result.copy()

        output_result, _ = ldap_group_allow_to_gateway_format(original_result, None, deny=False)

        # Original list should be unchanged
        assert original_result == result_copy
        # Output should be the same reference
        assert output_result is original_result

    def test_empty_string_group(self):
        """Test handling of empty string group."""
        result = []

        output_result, next_order = ldap_group_allow_to_gateway_format(result, "", deny=False, start_order=1)

        # Should still create a mapper even with empty string
        assert len(output_result) == 1
        assert output_result[0]["triggers"]["groups"]["has_and"] == [""]
        assert next_order == 2


# Parametrized tests for ldap_group_allow_to_gateway_format
@pytest.mark.parametrize(
    "ldap_group,deny,expected_name,expected_revoke,expected_trigger_type",
    [
        ("cn=test,dc=example,dc=com", True, "LDAP-DenyGroup", True, "has_or"),
        ("cn=test,dc=example,dc=com", False, "LDAP-RequireGroup", False, "has_and"),
        ("cn=users,ou=groups,dc=company,dc=com", True, "LDAP-DenyGroup", True, "has_or"),
        ("cn=users,ou=groups,dc=company,dc=com", False, "LDAP-RequireGroup", False, "has_and"),
    ],
)
def test_ldap_group_parametrized(ldap_group, deny, expected_name, expected_revoke, expected_trigger_type):
    """Parametrized test for various LDAP group configurations."""
    result = []

    output_result, next_order = ldap_group_allow_to_gateway_format(result, ldap_group, deny=deny, start_order=1)

    assert len(output_result) == 1
    mapper = output_result[0]

    assert mapper["name"] == expected_name
    assert mapper["revoke"] == expected_revoke
    assert expected_trigger_type in mapper["triggers"]["groups"]
    assert mapper["triggers"]["groups"][expected_trigger_type] == [ldap_group]
    assert next_order == 2


def test_realistic_awx_ldap_migration_scenario():
    """Test realistic scenario from AWX LDAP migration."""
    result = []

    # Simulate AWX LDAP configuration with both REQUIRE_GROUP and DENY_GROUP
    deny_group = "cn=blocked_users,OU=blocked groups,DC=contoso,DC=com"
    require_group = "cn=awx_users,OU=application groups,DC=contoso,DC=com"

    # Add deny group first (as in the migrator)
    result, next_order = ldap_group_allow_to_gateway_format(result, deny_group, deny=True, start_order=1)

    # Add require group second
    result, next_order = ldap_group_allow_to_gateway_format(result, require_group, deny=False, start_order=next_order)

    # Should have 2 allow mappers
    assert len(result) == 2

    # Verify deny group mapper
    deny_mapper = result[0]
    assert deny_mapper["name"] == "LDAP-DenyGroup"
    assert deny_mapper["map_type"] == "allow"
    assert deny_mapper["revoke"] is True
    assert deny_mapper["triggers"]["groups"]["has_or"] == [deny_group]
    assert deny_mapper["order"] == 1

    # Verify require group mapper
    require_mapper = result[1]
    assert require_mapper["name"] == "LDAP-RequireGroup"
    assert require_mapper["map_type"] == "allow"
    assert require_mapper["revoke"] is False
    assert require_mapper["triggers"]["groups"]["has_and"] == [require_group]
    assert require_mapper["order"] == 2

    assert next_order == 3
