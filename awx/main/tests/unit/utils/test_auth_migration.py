"""
Unit tests for auth migration utilities.
"""

import pytest
from awx.main.utils.gateway_mapping import org_map_to_gateway_format, team_map_to_gateway_format, role_map_to_gateway_format


def get_org_mappers(org_map, start_order=1):
    """Helper function to get just the mappers from org_map_to_gateway_format."""
    result, _ = org_map_to_gateway_format(org_map, start_order)
    return result


def get_team_mappers(team_map, start_order=1):
    """Helper function to get just the mappers from team_map_to_gateway_format."""
    result, _ = team_map_to_gateway_format(team_map, start_order)
    return result


def get_role_mappers(role_map, start_order=1):
    """Helper function to get just the mappers from role_map_to_gateway_format."""
    result, _ = role_map_to_gateway_format(role_map, start_order)
    return result


class TestOrgMapToGatewayFormat:

    def test_none_input(self):
        """Test that None input returns empty list."""
        result, next_order = org_map_to_gateway_format(None)
        assert result == []
        assert next_order == 1  # Default start_order

    def test_empty_dict(self):
        """Test that empty dict returns empty list."""
        result, next_order = org_map_to_gateway_format({})
        assert result == []
        assert next_order == 1

    def test_single_org_with_admin_true(self):
        """Test organization with admin access set to True."""
        org_map = {"myorg": {"admins": True}}

        result, _ = org_map_to_gateway_format(org_map)

        expected = [
            {
                "name": "myorg - Organization Admins",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "myorg",
                "triggers": {"always": {}},
                "role": "Organization Admin",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_single_org_with_admin_false(self):
        """Test organization with admin access set to False."""
        org_map = {"myorg": {"admins": False}}

        result, _ = org_map_to_gateway_format(org_map)

        expected = [
            {
                "name": "myorg - Organization Admins",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "myorg",
                "triggers": {"never": {}},
                "role": "Organization Admin",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_single_org_with_admin_string(self):
        """Test organization with admin access set to a specific group."""
        org_map = {"myorg": {"admins": "admin-group"}}

        result, _ = org_map_to_gateway_format(org_map)

        expected = [
            {
                "name": "myorg - Organization Admins",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "myorg",
                "triggers": {"groups": {"has_or": ["admin-group"]}},
                "role": "Organization Admin",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_single_org_with_admin_list(self):
        """Test organization with admin access set to multiple groups."""
        org_map = {"myorg": {"admins": ["admin-group1", "admin-group2"]}}

        result, _ = org_map_to_gateway_format(org_map)

        expected = [
            {
                "name": "myorg - Organization Admins",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "myorg",
                "triggers": {"groups": {"has_or": ["admin-group1", "admin-group2"]}},
                "role": "Organization Admin",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_single_org_with_users_true(self):
        """Test organization with user access set to True."""
        org_map = {"myorg": {"users": True}}

        result, _ = org_map_to_gateway_format(org_map)

        expected = [
            {
                "name": "myorg - Organization Users",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "myorg",
                "triggers": {"always": {}},
                "role": "Organization Member",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_single_org_with_both_admin_and_users(self):
        """Test organization with both admin and user mappings."""
        org_map = {"myorg": {"admins": True, "users": ["user-group"]}}

        result, _ = org_map_to_gateway_format(org_map)

        expected = [
            {
                "name": "myorg - Organization Admins",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "myorg",
                "triggers": {"always": {}},
                "role": "Organization Admin",
                "revoke": False,
                "order": 1,
            },
            {
                "name": "myorg - Organization Users",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "myorg",
                "triggers": {"groups": {"has_or": ["user-group"]}},
                "role": "Organization Member",
                "revoke": False,
                "order": 2,
            },
        ]

        assert result == expected

    def test_single_org_with_remove_admins(self):
        """Test organization with remove_admins flag."""
        org_map = {"myorg": {"admins": True, "remove_admins": True}}

        result, _ = org_map_to_gateway_format(org_map)

        expected = [
            {
                "name": "myorg - Organization Admins",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "myorg",
                "triggers": {"always": {}},
                "role": "Organization Admin",
                "revoke": True,
                "order": 1,
            }
        ]

        assert result == expected

    def test_single_org_with_remove_users(self):
        """Test organization with remove_users flag."""
        org_map = {"myorg": {"users": True, "remove_users": True}}

        result, _ = org_map_to_gateway_format(org_map)

        expected = [
            {
                "name": "myorg - Organization Users",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "myorg",
                "triggers": {"always": {}},
                "role": "Organization Member",
                "revoke": True,
                "order": 1,
            }
        ]

        assert result == expected

    def test_multiple_organizations(self):
        """Test multiple organizations with different configurations."""
        org_map = {"org1": {"admins": True}, "org2": {"users": ["group1", "group2"]}}

        result, _ = org_map_to_gateway_format(org_map)

        expected = [
            {
                "name": "org1 - Organization Admins",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "org1",
                "triggers": {"always": {}},
                "role": "Organization Admin",
                "revoke": False,
                "order": 1,
            },
            {
                "name": "org2 - Organization Users",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "org2",
                "triggers": {"groups": {"has_or": ["group1", "group2"]}},
                "role": "Organization Member",
                "revoke": False,
                "order": 2,
            },
        ]

        assert result == expected

    def test_org_with_none_values_skipped(self):
        """Test that entries with None values are skipped."""
        org_map = {"myorg": {"admins": None, "users": True}}

        result, _ = org_map_to_gateway_format(org_map)

        expected = [
            {
                "name": "myorg - Organization Users",
                "authenticator": -1,
                "map_type": "organization",
                "team": None,
                "organization": "myorg",
                "triggers": {"always": {}},
                "role": "Organization Member",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_order_increments_correctly(self):
        """Test that order values increment correctly."""
        org_map = {"myorg": {"admins": True, "users": True}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 2
        assert result[0]["order"] == 1
        assert result[1]["order"] == 2

    def test_triggers_format_validation(self):
        """Test that trigger formats match Gateway specification."""
        org_map = {"myorg": {"admins": ["group1", "group2"]}}

        result, _ = org_map_to_gateway_format(org_map)

        # Validate that triggers follow Gateway format
        triggers = result[0]["triggers"]
        assert "groups" in triggers
        assert "has_or" in triggers["groups"]
        assert isinstance(triggers["groups"]["has_or"], list)
        assert triggers["groups"]["has_or"] == ["group1", "group2"]

    def test_string_to_list_conversion(self):
        """Test that string groups are converted to lists."""
        org_map = {"myorg": {"users": "single-group"}}

        result, _ = org_map_to_gateway_format(org_map)

        # Should convert string to list for has_or
        assert result[0]["triggers"]["groups"]["has_or"] == ["single-group"]


class TestTeamMapToGatewayFormat:
    """Tests for team_map_to_gateway_format function."""

    def test_none_input(self):
        """Test that None input returns empty list."""
        result, next_order = team_map_to_gateway_format(None)
        assert result == []
        assert next_order == 1  # Default start_order

    def test_empty_dict(self):
        """Test that empty dict returns empty list."""
        result, next_order = team_map_to_gateway_format({})
        assert result == []
        assert next_order == 1

    def test_single_team_with_users_true(self):
        """Test team with users access set to True."""
        team_map = {"engineering-team": {"organization": "myorg", "users": True}}

        result, _ = team_map_to_gateway_format(team_map)

        expected = [
            {
                "name": "myorg - engineering-team",
                "authenticator": -1,
                "map_type": "team",
                "team": "engineering-team",
                "organization": "myorg",
                "triggers": {"always": {}},
                "role": "Team Member",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_single_team_with_users_false(self):
        """Test team with users access set to False."""
        team_map = {"dev-team": {"organization": "myorg", "users": False}}

        result, _ = team_map_to_gateway_format(team_map)

        expected = [
            {
                "name": "myorg - dev-team",
                "authenticator": -1,
                "map_type": "team",
                "team": "dev-team",
                "organization": "myorg",
                "triggers": {"never": {}},
                "role": "Team Member",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_single_team_with_users_string(self):
        """Test team with users access set to a specific group."""
        team_map = {"qa-team": {"organization": "myorg", "users": "qa-group"}}

        result, _ = team_map_to_gateway_format(team_map)

        expected = [
            {
                "name": "myorg - qa-team",
                "authenticator": -1,
                "map_type": "team",
                "team": "qa-team",
                "organization": "myorg",
                "triggers": {"groups": {"has_or": ["qa-group"]}},
                "role": "Team Member",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_single_team_with_users_list(self):
        """Test team with users access set to multiple groups."""
        team_map = {"ops-team": {"organization": "myorg", "users": ["ops-group1", "ops-group2"]}}

        result, _ = team_map_to_gateway_format(team_map)

        expected = [
            {
                "name": "myorg - ops-team",
                "authenticator": -1,
                "map_type": "team",
                "team": "ops-team",
                "organization": "myorg",
                "triggers": {"groups": {"has_or": ["ops-group1", "ops-group2"]}},
                "role": "Team Member",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_team_with_remove_flag(self):
        """Test team with remove flag set to True."""
        team_map = {"legacy-team": {"organization": "myorg", "users": True, "remove": True}}

        result, _ = team_map_to_gateway_format(team_map)

        expected = [
            {
                "name": "myorg - legacy-team",
                "authenticator": -1,
                "map_type": "team",
                "team": "legacy-team",
                "organization": "myorg",
                "triggers": {"always": {}},
                "role": "Team Member",
                "revoke": True,
                "order": 1,
            }
        ]

        assert result == expected

    def test_team_with_no_organization(self):
        """Test team without organization specified."""
        team_map = {"orphan-team": {"users": True}}

        result, _ = team_map_to_gateway_format(team_map)

        expected = [
            {
                "name": "Unknown - orphan-team",
                "authenticator": -1,
                "map_type": "team",
                "team": "orphan-team",
                "organization": "Unknown",
                "triggers": {"always": {}},
                "role": "Team Member",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_multiple_teams(self):
        """Test multiple teams with different configurations."""
        team_map = {"team1": {"organization": "org1", "users": True}, "team2": {"organization": "org2", "users": ["group1", "group2"]}}

        result, _ = team_map_to_gateway_format(team_map)

        expected = [
            {
                "name": "org1 - team1",
                "authenticator": -1,
                "map_type": "team",
                "team": "team1",
                "organization": "org1",
                "triggers": {"always": {}},
                "role": "Team Member",
                "revoke": False,
                "order": 1,
            },
            {
                "name": "org2 - team2",
                "authenticator": -1,
                "map_type": "team",
                "team": "team2",
                "organization": "org2",
                "triggers": {"groups": {"has_or": ["group1", "group2"]}},
                "role": "Team Member",
                "revoke": False,
                "order": 2,
            },
        ]

        assert result == expected

    def test_team_with_none_users_skipped(self):
        """Test that teams with None users are skipped."""
        team_map = {"skipped-team": {"organization": "myorg", "users": None}, "valid-team": {"organization": "myorg", "users": True}}

        result, _ = team_map_to_gateway_format(team_map)

        expected = [
            {
                "name": "myorg - valid-team",
                "authenticator": -1,
                "map_type": "team",
                "team": "valid-team",
                "organization": "myorg",
                "triggers": {"always": {}},
                "role": "Team Member",
                "revoke": False,
                "order": 1,
            }
        ]

        assert result == expected

    def test_order_increments_correctly(self):
        """Test that order values increment correctly for teams."""
        team_map = {"team1": {"organization": "myorg", "users": True}, "team2": {"organization": "myorg", "users": True}}

        result, _ = team_map_to_gateway_format(team_map)

        assert len(result) == 2
        assert result[0]["order"] == 1
        assert result[1]["order"] == 2

    def test_string_to_list_conversion(self):
        """Test that string groups are converted to lists."""
        team_map = {"myteam": {"organization": "myorg", "users": "single-group"}}

        result, _ = team_map_to_gateway_format(team_map)

        # Should convert string to list for has_or
        assert result[0]["triggers"]["groups"]["has_or"] == ["single-group"]

    def test_team_triggers_format_validation(self):
        """Test that team trigger formats match Gateway specification."""
        team_map = {"myteam": {"organization": "myorg", "users": ["group1", "group2"]}}

        result, _ = team_map_to_gateway_format(team_map)

        # Validate that triggers follow Gateway format
        triggers = result[0]["triggers"]
        assert "groups" in triggers
        assert "has_or" in triggers["groups"]
        assert isinstance(triggers["groups"]["has_or"], list)
        assert triggers["groups"]["has_or"] == ["group1", "group2"]

    def test_team_with_regex_patterns(self):
        """Test that teams with regex patterns in users are handled correctly."""
        team_map = {
            "My Team": {"organization": "Test Org", "users": ["/^[^@]+?@test\\.example\\.com$/"], "remove": True},
            "Other Team": {"organization": "Test Org 2", "users": ["/^[^@]+?@test\\.example\\.com$/"], "remove": False},
        }

        result, _ = team_map_to_gateway_format(team_map)

        expected = [
            {
                "name": "Test Org - My Team",
                "authenticator": -1,
                "map_type": "team",
                "team": "My Team",
                "organization": "Test Org",
                "triggers": {"groups": {"has_or": ["/^[^@]+?@test\\.example\\.com$/"]}},
                "role": "Team Member",
                "revoke": True,
                "order": 1,
            },
            {
                "name": "Test Org 2 - Other Team",
                "authenticator": -1,
                "map_type": "team",
                "team": "Other Team",
                "organization": "Test Org 2",
                "triggers": {"groups": {"has_or": ["/^[^@]+?@test\\.example\\.com$/"]}},
                "role": "Team Member",
                "revoke": False,
                "order": 2,
            },
        ]

        assert result == expected

        # Validate that the result is JSON serializable
        import json

        json_str = json.dumps(result)
        assert json_str is not None


# Parametrized tests for edge cases
@pytest.mark.parametrize(
    "org_map,expected_length",
    [
        (None, 0),
        ({}, 0),
        ({"org1": {}}, 0),  # Organization with no admin/user mappings
        ({"org1": {"admins": True}}, 1),
        ({"org1": {"users": True}}, 1),
        ({"org1": {"admins": True, "users": True}}, 2),
        ({"org1": {"admins": True}, "org2": {"users": True}}, 2),
    ],
)
def test_org_map_result_lengths(org_map, expected_length):
    """Test that org_map_to_gateway_format returns expected number of mappings."""
    result, _ = org_map_to_gateway_format(org_map)
    assert len(result) == expected_length


# Test for Gateway format compliance
@pytest.mark.parametrize(
    "org_map",
    [
        {"org1": {"admins": True}},
        {"org1": {"users": ["group1"]}},
        {"org1": {"admins": False}},
    ],
)
def test_gateway_format_compliance(org_map):
    """Test that all results comply with Gateway mapping format."""
    result, _ = org_map_to_gateway_format(org_map)

    for mapping in result:
        # Required fields per Gateway spec
        assert "name" in mapping
        assert "authenticator" in mapping
        assert "map_type" in mapping
        assert "organization" in mapping
        assert "team" in mapping
        assert "triggers" in mapping
        assert "role" in mapping
        assert "revoke" in mapping
        assert "order" in mapping

        # Field types
        assert isinstance(mapping["name"], str)
        assert isinstance(mapping["authenticator"], int)
        assert mapping["map_type"] == "organization"  # For org mappings
        assert isinstance(mapping["organization"], str)
        assert mapping["team"] is None  # For org mappings, team should be None
        assert isinstance(mapping["triggers"], dict)
        assert isinstance(mapping["role"], str)
        assert isinstance(mapping["revoke"], bool)
        assert isinstance(mapping["order"], int)


# Parametrized tests for team mappings
@pytest.mark.parametrize(
    "team_map,expected_length",
    [
        (None, 0),
        ({}, 0),
        ({"team1": {"organization": "org1", "users": None}}, 0),  # Team with None users should be skipped
        ({"team1": {"organization": "org1", "users": True}}, 1),
        ({"team1": {"organization": "org1", "users": ["group1"]}}, 1),
        ({"team1": {"organization": "org1", "users": True}, "team2": {"organization": "org2", "users": False}}, 2),
    ],
)
def test_team_map_result_lengths(team_map, expected_length):
    """Test that team_map_to_gateway_format returns expected number of mappings."""
    result, _ = team_map_to_gateway_format(team_map)
    assert len(result) == expected_length


# Test for Gateway format compliance for teams
@pytest.mark.parametrize(
    "team_map",
    [
        {"team1": {"organization": "org1", "users": True}},
        {"team1": {"organization": "org1", "users": ["group1"]}},
        {"team1": {"organization": "org1", "users": False}},
    ],
)
def test_team_gateway_format_compliance(team_map):
    """Test that all team results comply with Gateway mapping format."""
    result, _ = team_map_to_gateway_format(team_map)

    for mapping in result:
        # Required fields per Gateway spec
        assert "name" in mapping
        assert "authenticator" in mapping
        assert "map_type" in mapping
        assert "organization" in mapping
        assert "team" in mapping
        assert "triggers" in mapping
        assert "role" in mapping
        assert "revoke" in mapping
        assert "order" in mapping

        # Field types
        assert isinstance(mapping["name"], str)
        assert isinstance(mapping["authenticator"], int)
        assert mapping["map_type"] == "team"  # For team mappings
        assert isinstance(mapping["organization"], str)
        assert isinstance(mapping["team"], str)
        assert isinstance(mapping["triggers"], dict)
        assert isinstance(mapping["role"], str)
        assert isinstance(mapping["revoke"], bool)
        assert isinstance(mapping["order"], int)
