"""
Unit tests for auth migration utilities.
"""

import pytest
import re
from awx.main.utils.gateway_mapping import (
    org_map_to_gateway_format,
    team_map_to_gateway_format,
    role_map_to_gateway_format,
    process_sso_user_list,
    process_ldap_user_list,
)


def get_org_mappers(org_map, start_order=1, auth_type='sso'):
    """Helper function to get just the mappers from org_map_to_gateway_format."""
    result, _ = org_map_to_gateway_format(org_map, start_order, auth_type=auth_type)
    return result


def get_team_mappers(team_map, start_order=1, auth_type='sso'):
    """Helper function to get just the mappers from team_map_to_gateway_format."""
    result, _ = team_map_to_gateway_format(team_map, start_order, auth_type=auth_type)
    return result


def get_role_mappers(role_map, start_order=1):
    """Helper function to get just the mappers from role_map_to_gateway_format."""
    result, _ = role_map_to_gateway_format(role_map, start_order)
    return result


class TestProcessSSOUserList:
    """Tests for the process_sso_user_list function (consolidated version)."""

    def test_false_boolean(self):
        """Test that False creates 'Never Allow' trigger."""
        result = process_sso_user_list(False)

        assert result["name"] == "Never Allow"
        assert result["trigger"] == {"never": {}}

    def test_true_boolean(self):
        """Test that True creates 'Always Allow' trigger."""
        result = process_sso_user_list(True)

        assert result["name"] == "Always Allow"
        assert result["trigger"] == {"always": {}}

    def test_false_string_list(self):
        """Test that ['false'] creates 'Never Allow' trigger."""
        result = process_sso_user_list(["false"])

        assert result["name"] == "Never Allow"
        assert result["trigger"] == {"never": {}}

    def test_true_string_list(self):
        """Test that ['true'] creates 'Always Allow' trigger."""
        result = process_sso_user_list(["true"])

        assert result["name"] == "Always Allow"
        assert result["trigger"] == {"always": {}}

    def test_string_user_list(self):
        """Test that regular string users are processed correctly."""
        result = process_sso_user_list(["testuser"])

        assert result["name"] == "U:1"
        assert result["trigger"]["attributes"]["username"]["equals"] == "testuser"

    def test_email_user_list(self):
        """Test that email addresses are processed correctly."""
        result = process_sso_user_list(["test@example.com"])

        assert result["name"] == "E:1"
        assert result["trigger"]["attributes"]["email"]["equals"] == "test@example.com"

    def test_mixed_string_list(self):
        """Test that mixed list with 'true', 'false', and regular users works correctly."""
        result = process_sso_user_list(["true", "testuser", "false"])

        # Should consolidate all usernames and show count
        assert result["name"] == "U:3"
        assert result["trigger"]["attributes"]["username"]["in"] == ["true", "testuser", "false"]

    def test_custom_email_username_attrs(self):
        """Test that custom email and username attributes work correctly."""
        result = process_sso_user_list(["test@example.com"], email_attr='custom_email', username_attr='custom_username')

        assert result["trigger"]["attributes"]["custom_email"]["equals"] == "test@example.com"

    def test_regex_pattern(self):
        """Test that regex patterns create both username and email matches."""
        pattern = re.compile(r"^admin.*@example\.com$")
        result = process_sso_user_list([pattern])

        assert result["name"] == "UP:1 EP:1"
        assert result["trigger"]["attributes"]["username"]["matches"] == "/^admin.*@example\\.com$/"
        assert result["trigger"]["attributes"]["email"]["matches"] == "/^admin.*@example\\.com$/"

    def test_multiple_emails(self):
        """Test that multiple emails use count-based names."""
        emails = [f"user{i}@example.com" for i in range(10)]
        result = process_sso_user_list(emails)

        assert result["name"] == "E:10"
        assert result["trigger"]["attributes"]["email"]["in"] == emails

    def test_multiple_usernames(self):
        """Test that multiple usernames use count-based names."""
        usernames = [f"user{i}" for i in range(8)]
        result = process_sso_user_list(usernames)

        assert result["name"] == "U:8"
        assert result["trigger"]["attributes"]["username"]["in"] == usernames

    def test_mixed_emails_and_usernames(self):
        """Test mixed emails and usernames use count-based names."""
        emails = ["user1@example.com", "user2@example.com"]
        usernames = ["admin1", "admin2", "admin3"]
        users = emails + usernames
        result = process_sso_user_list(users)

        assert result["name"] == "E:2 U:3"
        assert result["trigger"]["attributes"]["email"]["in"] == emails
        assert result["trigger"]["attributes"]["username"]["in"] == usernames

    def test_multiple_regex_patterns(self):
        """Test that multiple regex patterns use count-based names."""
        patterns = [re.compile(f"pattern{i}") for i in range(5)]
        result = process_sso_user_list(patterns)

        assert result["name"] == "UP:5 EP:5"

    def test_empty_list(self):
        """Test that empty list creates default trigger."""
        result = process_sso_user_list([])
        assert result["name"] == "Mixed Rules"
        assert result["trigger"]["attributes"]["join_condition"] == "or"


class TestProcessLdapUserList:
    """Tests for the process_ldap_user_list function."""

    def test_none_input(self):
        """Test that None creates no triggers (empty list)."""
        result = process_ldap_user_list(None)
        assert len(result) == 0

    def test_none_in_list(self):
        """Test that [None] creates no triggers (empty list)."""
        result = process_ldap_user_list([None])
        assert len(result) == 0

    def test_true_boolean(self):
        """Test that True creates 'Always Allow' trigger."""
        result = process_ldap_user_list(True)
        assert len(result) == 1
        assert result[0]["name"] == "Always Allow"
        assert result[0]["trigger"] == {"always": {}}

    def test_true_boolean_in_list(self):
        """Test that [True] creates 'Always Allow' trigger."""
        result = process_ldap_user_list([True])
        assert len(result) == 1
        assert result[0]["name"] == "Always Allow"
        assert result[0]["trigger"] == {"always": {}}

    def test_false_boolean(self):
        """Test that False creates 'Never Allow' trigger."""
        result = process_ldap_user_list(False)
        assert len(result) == 1
        assert result[0]["name"] == "Never Allow"
        assert result[0]["trigger"] == {"never": {}}

    def test_false_boolean_in_list(self):
        """Test that [False] creates 'Never Allow' trigger."""
        result = process_ldap_user_list([False])
        assert len(result) == 1
        assert result[0]["name"] == "Never Allow"
        assert result[0]["trigger"] == {"never": {}}

    def test_single_string_group(self):
        """Test that a single string creates group match trigger."""
        result = process_ldap_user_list("admin_group")
        assert len(result) == 1
        assert result[0]["name"] == "Match User Groups"
        assert result[0]["trigger"]["groups"]["has_or"] == ["admin_group"]

    def test_single_string_group_in_list(self):
        """Test that a single string in list creates group match trigger."""
        result = process_ldap_user_list(["admin_group"])
        assert len(result) == 1
        assert result[0]["name"] == "Match User Groups"
        assert result[0]["trigger"]["groups"]["has_or"] == ["admin_group"]

    def test_multiple_groups(self):
        """Test that multiple groups create single trigger with all groups."""
        result = process_ldap_user_list(["group1", "group2", "group3"])
        assert len(result) == 1
        assert result[0]["name"] == "Match User Groups"
        assert result[0]["trigger"]["groups"]["has_or"] == ["group1", "group2", "group3"]

    def test_mixed_types_with_none(self):
        """Test that mixed types including None are handled correctly."""
        result = process_ldap_user_list(["group1", None, "group2"])
        assert len(result) == 1
        assert result[0]["name"] == "Match User Groups"
        assert result[0]["trigger"]["groups"]["has_or"] == ["group1", None, "group2"]

    def test_mixed_types_with_boolean_string(self):
        """Test that boolean values mixed with strings are handled correctly."""
        result = process_ldap_user_list(["group1", False, "group2"])
        assert len(result) == 1
        assert result[0]["name"] == "Match User Groups"
        assert result[0]["trigger"]["groups"]["has_or"] == ["group1", False, "group2"]

    def test_empty_list(self):
        """Test that empty list creates no triggers."""
        result = process_ldap_user_list([])
        assert len(result) == 0

    def test_numeric_values(self):
        """Test that numeric values are handled correctly."""
        result = process_ldap_user_list([123, "group1"])
        assert len(result) == 1
        assert result[0]["name"] == "Match User Groups"
        assert result[0]["trigger"]["groups"]["has_or"] == [123, "group1"]


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

    def test_order_increments_correctly(self):
        """Test that order values increment correctly."""
        org_map = {"myorg": {"admins": True, "users": True}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 2
        assert result[0]["order"] == 1
        assert result[1]["order"] == 2

    def test_org_with_admin_true(self):
        """Test organization with admin access set to True."""
        org_map = {"myorg": {"admins": True}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 1
        mapping = result[0]
        assert mapping["name"] == "myorg - Admins Always Allow"
        assert mapping["map_type"] == "organization"
        assert mapping["organization"] == "myorg"
        assert mapping["team"] is None
        assert mapping["role"] == "Organization Admin"
        assert mapping["revoke"] is False
        assert mapping["order"] == 1
        assert mapping["triggers"] == {"always": {}}

    def test_org_with_admin_false(self):
        """Test organization with admin access set to False."""
        org_map = {"myorg": {"admins": False}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 1
        mapping = result[0]
        assert mapping["name"] == "myorg - Admins Never Allow"
        assert mapping["triggers"] == {"never": {}}
        assert mapping["role"] == "Organization Admin"

    def test_org_with_admin_false_string(self):
        """Test organization with admin access set to ['false']."""
        org_map = {"myorg": {"admins": ["false"]}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 1
        mapping = result[0]
        assert mapping["name"] == "myorg - Admins Never Allow"
        assert mapping["triggers"] == {"never": {}}
        assert mapping["role"] == "Organization Admin"

    def test_org_with_users_true_string(self):
        """Test organization with users access set to ['true']."""
        org_map = {"myorg": {"users": ["true"]}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 1
        mapping = result[0]
        assert mapping["name"] == "myorg - Users Always Allow"
        assert mapping["triggers"] == {"always": {}}
        assert mapping["role"] == "Organization Member"

    def test_org_with_users_true(self):
        """Test organization with users access set to True."""
        org_map = {"myorg": {"users": True}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 1
        mapping = result[0]
        assert mapping["name"] == "myorg - Users Always Allow"
        assert mapping["triggers"] == {"always": {}}
        assert mapping["role"] == "Organization Member"

    def test_org_with_admin_string(self):
        """Test organization with admin access set to a specific group."""
        org_map = {"myorg": {"admins": "admin-username"}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 1
        mapping = result[0]
        assert mapping["name"] == "myorg - Admins U:1"
        assert mapping["triggers"] == {"attributes": {"join_condition": "or", "username": {"equals": "admin-username"}}}
        assert mapping["role"] == "Organization Admin"

    def test_org_with_admin_list(self):
        """Test organization with admin access set to multiple groups."""
        org_map = {"myorg": {"admins": ["admin-username1", "admin-username2"]}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 1
        mapping = result[0]
        assert mapping["name"] == "myorg - Admins U:2"
        assert mapping["triggers"]["attributes"]["username"]["in"] == ["admin-username1", "admin-username2"]
        assert mapping["order"] == 1

    def test_org_with_email_detection(self):
        """Test that email addresses are correctly identified and handled."""
        org_map = {"myorg": {"users": ["user@example.com", "admin@test.org", "not-an-email"]}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 1
        mapping = result[0]

        # Should consolidate emails and usernames in one mapper
        assert mapping["name"] == "myorg - Users E:2 U:1"

        # Should have both email and username attributes
        assert mapping["triggers"]["attributes"]["email"]["in"] == ["user@example.com", "admin@test.org"]
        assert mapping["triggers"]["attributes"]["username"]["equals"] == "not-an-email"
        assert mapping["triggers"]["attributes"]["join_condition"] == "or"

    def test_org_with_remove_flags(self):
        """Test organization with remove flags."""
        org_map = {"myorg": {"admins": True, "users": ["user-group"], "remove_admins": True, "remove_users": True}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 2
        assert result[0]["revoke"] is True  # admin mapping should have revoke=True
        assert result[1]["revoke"] is True  # user mapping should have revoke=True

    def test_org_with_custom_email_username_attrs(self):
        """Test org mapping with custom email and username attributes."""
        org_map = {"myorg": {"admins": ["test@example.com"]}}

        result, _ = org_map_to_gateway_format(org_map, email_attr='custom_email', username_attr='custom_username')

        assert len(result) == 1
        mapping = result[0]
        assert mapping["triggers"]["attributes"]["custom_email"]["equals"] == "test@example.com"

    def test_org_with_regex_pattern_objects(self):
        """Test org mapping with actual re.Pattern objects."""
        regex_str = "^admin.*@example\\.com$"

        org_map = {"myorg": {"users": [re.compile(regex_str)]}}

        result, _ = org_map_to_gateway_format(org_map)

        # Should create 1 consolidated mapping with both username and email matches
        assert len(result) == 1, f"Expected 1 item but got: {result}"

        mapping = result[0]
        assert mapping["name"] == "myorg - Users UP:1 EP:1"
        assert mapping["triggers"]["attributes"]["username"]["matches"] == f"/{regex_str}/"
        assert mapping["triggers"]["attributes"]["email"]["matches"] == f"/{regex_str}/"

    def test_org_with_none_values_skipped(self):
        """Test that entries with None values are skipped."""
        org_map = {"myorg": {"admins": None, "users": True}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 1
        assert result[0]["role"] == "Organization Member"  # Only users mapping should be present

    def test_org_with_start_order_parameter(self):
        """Test that start_order parameter works correctly."""
        org_map = {"org1": {"admins": True}, "org2": {"users": ["username1", "username2"]}}

        result, next_order = org_map_to_gateway_format(org_map, start_order=10)

        # Should have 2 mappings total (1 for org1, 1 for org2)
        assert len(result) == 2
        assert result[0]["order"] == 10
        assert result[1]["order"] == 11
        assert next_order == 12

    def test_org_comprehensive_field_validation(self):
        """Test comprehensive validation of all fields in org mappings."""
        org_map = {"test-org": {"admins": ["test-admin"], "remove_admins": False}}

        result, next_order = org_map_to_gateway_format(org_map, start_order=5)

        assert len(result) == 1
        mapping = result[0]

        # Validate all required fields and their types
        assert isinstance(mapping["name"], str)
        assert mapping["name"] == "test-org - Admins U:1"

        assert mapping["map_type"] == "organization"
        assert mapping["order"] == 5
        assert mapping["authenticator"] == -1

        assert isinstance(mapping["triggers"], dict)
        assert "attributes" in mapping["triggers"]

        assert mapping["organization"] == "test-org"
        assert mapping["team"] is None
        assert mapping["role"] == "Organization Admin"
        assert mapping["revoke"] is False

        # Validate next_order is incremented correctly
        assert next_order == 6

    def test_org_next_order_calculation(self):
        """Test that next_order is calculated correctly in various scenarios."""
        # Test with no orgs
        result, next_order = org_map_to_gateway_format({})
        assert next_order == 1

        # Test with orgs that have no admins/users (should be skipped)
        org_map = {"skipped": {"admins": None, "users": None}}
        result, next_order = org_map_to_gateway_format(org_map)
        assert len(result) == 0
        assert next_order == 1

        # Test with single org
        org_map = {"single": {"admins": True}}
        result, next_order = org_map_to_gateway_format(org_map)
        assert len(result) == 1
        assert next_order == 2

        # Test with multiple mappings from single org - now consolidated into one
        org_map = {"multi": {"users": ["user1", "user2"]}}
        result, next_order = org_map_to_gateway_format(org_map)
        assert len(result) == 1
        assert next_order == 2

    def test_org_with_auth_type_sso(self):
        """Test org mapping with auth_type='sso' (default behavior)."""
        org_map = {"myorg": {"users": ["testuser"]}}

        result, _ = org_map_to_gateway_format(org_map, auth_type='sso')

        assert len(result) == 1
        mapping = result[0]
        assert mapping["name"] == "myorg - Users U:1"
        assert mapping["triggers"]["attributes"]["username"]["equals"] == "testuser"

    def test_org_with_auth_type_ldap(self):
        """Test org mapping with auth_type='ldap'."""
        org_map = {"myorg": {"users": ["admin_group"]}}

        result, _ = org_map_to_gateway_format(org_map, auth_type='ldap')

        assert len(result) == 1
        mapping = result[0]
        assert "Match User Groups" in mapping["name"]
        assert mapping["triggers"]["groups"]["has_or"] == ["admin_group"]

    def test_org_with_auth_type_ldap_boolean(self):
        """Test org mapping with auth_type='ldap' and boolean values."""
        org_map = {"myorg": {"users": True, "admins": False}}

        result, _ = org_map_to_gateway_format(org_map, auth_type='ldap')

        assert len(result) == 2
        user_mapping = next(m for m in result if "Users" in m["name"])
        admin_mapping = next(m for m in result if "Admins" in m["name"])

        assert "Always Allow" in user_mapping["name"]
        assert user_mapping["triggers"]["always"] == {}

        assert "Never Allow" in admin_mapping["name"]
        assert admin_mapping["triggers"]["never"] == {}


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

    def test_order_increments_correctly(self):
        """Test that order values increment correctly for teams."""
        team_map = {"team1": {"organization": "myorg", "users": True}, "team2": {"organization": "myorg", "users": True}}

        result, _ = team_map_to_gateway_format(team_map)

        assert len(result) == 2
        assert result[0]["order"] == 1
        assert result[1]["order"] == 2

    def test_team_with_email_detection(self):
        """Test that email addresses are correctly identified and handled."""
        team_map = {"email-team": {"organization": "myorg", "users": ["user@example.com", "admin@test.org", "not-an-email"]}}

        result, _ = team_map_to_gateway_format(team_map)

        # Should have 1 consolidated mapping
        assert len(result) == 1
        mapping = result[0]

        # Should consolidate emails and usernames in one mapper
        assert mapping["name"] == "myorg - email-team E:2 U:1"

        # Should have both email and username attributes
        assert mapping["triggers"]["attributes"]["email"]["in"] == ["user@example.com", "admin@test.org"]
        assert mapping["triggers"]["attributes"]["username"]["equals"] == "not-an-email"
        assert mapping["triggers"]["attributes"]["join_condition"] == "or"

    def test_team_with_custom_email_username_attrs(self):
        """Test team mapping with custom email and username attributes."""
        team_map = {"custom-team": {"organization": "myorg", "users": ["test@example.com"]}}

        result, _ = team_map_to_gateway_format(team_map, email_attr='custom_email', username_attr='custom_username')

        assert len(result) == 1
        mapping = result[0]
        assert mapping["triggers"]["attributes"]["custom_email"]["equals"] == "test@example.com"
        assert mapping["name"] == "myorg - custom-team E:1"

    def test_team_with_regex_pattern_objects(self):
        """Test team mapping with actual re.Pattern objects."""
        regex_str = "^admin.*@example\\.com$"

        team_map = {"regex-team": {"organization": "myorg", "users": [re.compile(regex_str)]}}

        result, _ = team_map_to_gateway_format(team_map)

        # Should create 1 consolidated mapping with both username and email matches
        assert len(result) == 1, f"Expected 1 item but got: {result}"

        mapping = result[0]
        assert mapping["name"] == "myorg - regex-team UP:1 EP:1"
        assert mapping["triggers"]["attributes"]["username"]["matches"] == f"/{regex_str}/"
        assert mapping["triggers"]["attributes"]["email"]["matches"] == f"/{regex_str}/"

    def test_team_with_non_string_objects(self):
        """Test team mapping with non-string objects that get converted."""

        class CustomObject:
            def __str__(self):
                return "custom_object_string"

        custom_obj = CustomObject()
        team_map = {"object-team": {"organization": "myorg", "users": [custom_obj, 12345]}}

        result, _ = team_map_to_gateway_format(team_map)

        # Should create 1 consolidated mapping with both username and email attributes
        assert len(result) == 1

        mapping = result[0]
        # Both objects should be treated as usernames and emails
        assert mapping["triggers"]["attributes"]["username"]["in"] == ["custom_object_string", "12345"]
        assert mapping["triggers"]["attributes"]["email"]["in"] == ["custom_object_string", "12345"]

    def test_team_with_mixed_data_types(self):
        """Test team mapping with mixed data types in users list."""
        regex_str = 'test.*'

        team_map = {"mixed-team": {"organization": "myorg", "users": ["string_user", "email@test.com", re.compile(regex_str), 999, True]}}

        result, _ = team_map_to_gateway_format(team_map)

        # Should create 1 consolidated mapping with all types handled
        assert len(result) == 1

        mapping = result[0]
        # All types should be consolidated into one mapper name
        assert mapping["name"] == "myorg - mixed-team E:3 U:3 UP:1 EP:1"

        # Verify trigger structure contains all the data types
        triggers = mapping["triggers"]["attributes"]
        assert "email" in triggers
        assert "username" in triggers

    def test_team_with_start_order_parameter(self):
        """Test that start_order parameter works correctly."""
        team_map = {"team1": {"organization": "org1", "users": True}, "team2": {"organization": "org2", "users": ["username1", "username2"]}}

        result, next_order = team_map_to_gateway_format(team_map, start_order=10)

        # First mapping should start at order 10
        assert result[0]["order"] == 10
        # Should increment properly
        orders = [mapping["order"] for mapping in result]
        assert orders == sorted(orders)  # Should be in ascending order
        assert min(orders) == 10
        # next_order should be one more than the last used order
        assert next_order == max(orders) + 1

    def test_team_with_empty_strings(self):
        """Test team mapping with empty strings."""
        team_map = {
            "": {"organization": "myorg", "users": [""]},  # Empty team name and user
            "normal-team": {"organization": "", "users": True},  # Empty organization
        }

        result, _ = team_map_to_gateway_format(team_map)

        # Should handle empty strings gracefully
        assert len(result) == 2

        # Check empty team name mapping
        empty_team_mapping = [m for m in result if m["team"] == ""][0]
        assert " - " in empty_team_mapping["name"] and "U:1" in empty_team_mapping["name"]
        assert empty_team_mapping["team"] == ""

        # Check empty organization mapping
        empty_org_mapping = [m for m in result if m["organization"] == ""][0]
        assert empty_org_mapping["organization"] == ""
        assert "Always Allow" in empty_org_mapping["name"]

    def test_team_with_special_characters(self):
        """Test team mapping with special characters in names."""
        team_map = {
            "team-with-special!@#$%^&*()_+chars": {"organization": "org with spaces & symbols!", "users": ["user@domain.com", "user-with-special!chars"]}
        }

        result, _ = team_map_to_gateway_format(team_map)

        assert len(result) == 1

        # Verify special characters are preserved in names
        mapping = result[0]
        assert "team-with-special!@#$%^&*()_+chars" in mapping["name"]
        assert "org with spaces & symbols!" in mapping["name"]
        assert mapping["team"] == "team-with-special!@#$%^&*()_+chars"
        assert mapping["organization"] == "org with spaces & symbols!"

    def test_team_with_unicode_characters(self):
        """Test team mapping with unicode characters."""
        team_map = {
            "チーム": {  # Japanese for "team"
                "organization": "組織",  # Japanese for "organization"
                "users": ["ユーザー@example.com", "用户"],  # Mixed Japanese/Chinese
            }
        }

        result, _ = team_map_to_gateway_format(team_map)

        assert len(result) == 1

        # Verify unicode characters are handled correctly
        mapping = result[0]
        assert "チーム" in mapping["name"]
        assert "組織" in mapping["name"]
        assert mapping["team"] == "チーム"
        assert mapping["organization"] == "組織"

    def test_team_next_order_calculation(self):
        """Test that next_order is calculated correctly in various scenarios."""
        # Test with no teams
        result, next_order = team_map_to_gateway_format({})
        assert next_order == 1

        # Test with teams that have no users (should be skipped)
        team_map = {"skipped": {"organization": "org", "users": None}}
        result, next_order = team_map_to_gateway_format(team_map)
        assert len(result) == 0
        assert next_order == 1

        # Test with single team
        team_map = {"single": {"organization": "org", "users": True}}
        result, next_order = team_map_to_gateway_format(team_map)
        assert len(result) == 1
        assert next_order == 2

        # Test with multiple mappings from single team - now consolidated into one
        team_map = {"multi": {"organization": "org", "users": ["user1", "user2"]}}
        result, next_order = team_map_to_gateway_format(team_map)
        assert len(result) == 1
        assert next_order == 2

    def test_team_large_dataset_performance(self):
        """Test team mapping with a large number of teams and users."""
        # Create a large team map
        team_map = {}
        for i in range(100):
            team_map[f"team_{i}"] = {
                "organization": f"org_{i % 10}",  # 10 different orgs
                "users": [f"user_{j}@org_{i % 10}.com" for j in range(5)],  # 5 users per team
            }

        result, next_order = team_map_to_gateway_format(team_map)

        # Should create 100 mappings (1 per team, with consolidated users)
        assert len(result) == 100

        # Verify orders are sequential
        orders = [mapping["order"] for mapping in result]
        assert orders == list(range(1, 101))
        assert next_order == 101

        # Verify all teams are represented
        teams = {mapping["team"] for mapping in result}
        assert len(teams) == 100

    def test_team_mapping_field_validation(self):
        """Test that all required fields are present and have correct types."""
        team_map = {"validation-team": {"organization": "test-org", "users": ["test@example.com"], "remove": True}}

        result, _ = team_map_to_gateway_format(team_map)

        for mapping in result:
            # Check required fields exist
            required_fields = ["name", "map_type", "order", "authenticator", "triggers", "organization", "team", "role", "revoke"]
            for field in required_fields:
                assert field in mapping, f"Missing required field: {field}"

            # Check field types
            assert isinstance(mapping["name"], str)
            assert isinstance(mapping["map_type"], str)
            assert isinstance(mapping["order"], int)
            assert isinstance(mapping["authenticator"], int)
            assert isinstance(mapping["triggers"], dict)
            assert isinstance(mapping["organization"], str)
            assert isinstance(mapping["team"], str)
            assert isinstance(mapping["role"], str)
            assert isinstance(mapping["revoke"], bool)

            # Check specific values
            assert mapping["map_type"] == "team"
            assert mapping["authenticator"] == -1
            assert mapping["role"] == "Team Member"
            assert mapping["revoke"] == True  # Because remove was set to True

    def test_team_trigger_structure_validation(self):
        """Test that trigger structures are correctly formatted."""
        team_map = {"trigger-test": {"organization": "org", "users": ["test@example.com", "username"]}}

        result, _ = team_map_to_gateway_format(team_map)

        for mapping in result:
            triggers = mapping["triggers"]

            if "always" in triggers:
                assert triggers["always"] == {}
            elif "never" in triggers:
                assert triggers["never"] == {}
            elif "attributes" in triggers:
                attrs = triggers["attributes"]
                assert "join_condition" in attrs
                assert attrs["join_condition"] == "or"  # Implementation uses 'or'

                # Should have either username or email attribute
                assert ("username" in attrs) or ("email" in attrs)

                # The attribute should have either "equals", "matches", or "has_or"
                for attr_name in ["username", "email"]:
                    if attr_name in attrs:
                        attr_value = attrs[attr_name]
                        assert ("equals" in attr_value) or ("matches" in attr_value) or ("has_or" in attr_value)

    def test_team_boolean_false_trigger(self):
        """Test that False users value creates never trigger correctly."""
        team_map = {"never-team": {"organization": "org", "users": False}}

        result, _ = team_map_to_gateway_format(team_map)

        assert len(result) == 1
        mapping = result[0]
        assert mapping["triggers"] == {"never": {}}
        assert "Never Allow" in mapping["name"]

    def test_team_boolean_true_trigger(self):
        """Test that True users value creates always trigger correctly."""
        team_map = {"always-team": {"organization": "org", "users": True}}

        result, _ = team_map_to_gateway_format(team_map)

        assert len(result) == 1
        mapping = result[0]
        assert mapping["triggers"] == {"always": {}}
        assert "Always Allow" in mapping["name"]

    def test_team_string_false_trigger(self):
        """Test that ['false'] users value creates never trigger correctly."""
        team_map = {"never-team": {"organization": "org", "users": ["false"]}}

        result, _ = team_map_to_gateway_format(team_map)

        assert len(result) == 1
        mapping = result[0]
        assert mapping["triggers"] == {"never": {}}
        assert "Never Allow" in mapping["name"]

    def test_team_string_true_trigger(self):
        """Test that ['true'] users value creates always trigger correctly."""
        team_map = {"always-team": {"organization": "org", "users": ["true"]}}

        result, _ = team_map_to_gateway_format(team_map)

        assert len(result) == 1
        mapping = result[0]
        assert mapping["triggers"] == {"always": {}}
        assert "Always Allow" in mapping["name"]

    def test_team_with_join_condition_or(self):
        """Test that all attribute-based triggers use 'or' join condition."""
        team_map = {"test-team": {"organization": "org", "users": ["user1", "user2"]}}

        result, _ = team_map_to_gateway_format(team_map)

        for mapping in result:
            if "attributes" in mapping["triggers"]:
                assert mapping["triggers"]["attributes"]["join_condition"] == "or"

    def test_team_with_default_organization_fallback(self):
        """Test that teams without organization get 'Unknown' as default."""
        team_map = {"orphan-team": {"users": ["user1"]}}

        result, _ = team_map_to_gateway_format(team_map)

        assert len(result) == 1
        assert result[0]["organization"] == "Unknown"
        assert "Unknown - orphan-team" in result[0]["name"]

    def test_team_with_regex_string_patterns(self):
        """Test team mapping with regex patterns as strings (not compiled patterns)."""
        team_map = {"regex-team": {"organization": "myorg", "users": ["/^admin.*@example\\.com$/"]}}

        result, _ = team_map_to_gateway_format(team_map)

        # String patterns should be treated as regular strings, not regex
        assert len(result) == 1
        mapping = result[0]
        assert mapping["name"] == "myorg - regex-team U:1"
        assert mapping["triggers"]["attributes"]["username"]["equals"] == "/^admin.*@example\\.com$/"

    def test_team_comprehensive_field_validation(self):
        """Test comprehensive validation of all fields in team mappings."""
        team_map = {"comprehensive-team": {"organization": "test-org", "users": ["test-user"], "remove": False}}

        result, next_order = team_map_to_gateway_format(team_map, start_order=5)

        assert len(result) == 1
        mapping = result[0]

        # Validate all required fields and their types
        assert isinstance(mapping["name"], str)
        assert mapping["name"] == "test-org - comprehensive-team U:1"

        assert mapping["map_type"] == "team"
        assert mapping["order"] == 5
        assert mapping["authenticator"] == -1

        assert isinstance(mapping["triggers"], dict)
        assert "attributes" in mapping["triggers"]

        assert mapping["organization"] == "test-org"
        assert mapping["team"] == "comprehensive-team"
        assert mapping["role"] == "Team Member"
        assert mapping["revoke"] == False

        # Validate next_order is incremented correctly
        assert next_order == 6

    def test_team_with_none_and_remove_flag(self):
        """Test that teams with None users are skipped even with remove flag."""
        team_map = {
            "skipped-team": {"organization": "org", "users": None, "remove": True},
            "valid-team": {"organization": "org", "users": True, "remove": True},
        }

        result, _ = team_map_to_gateway_format(team_map)

        # Should only have one result (the valid team)
        assert len(result) == 1
        assert result[0]["team"] == "valid-team"
        assert result[0]["revoke"] == True

    def test_team_error_handling_edge_cases(self):
        """Test various edge cases for error handling."""
        # Test with completely empty team config
        team_map = {"empty-team": {}}

        try:
            _, _ = team_map_to_gateway_format(team_map)
            # Should not crash, but might skip the team due to missing 'users' key
        except KeyError:
            # This is expected if 'users' key is required
            pass

    def test_team_ordering_with_mixed_types(self):
        """Test that ordering works correctly with mixed user types."""
        team_map = {
            "team1": {"organization": "org1", "users": True},  # 1 mapping
            "team2": {"organization": "org2", "users": ["user1", "user2"]},  # 1 mapping (consolidated)
            "team3": {"organization": "org3", "users": False},  # 1 mapping
        }

        result, next_order = team_map_to_gateway_format(team_map, start_order=10)

        # Should have 3 total mappings (consolidated behavior)
        assert len(result) == 3

        # Orders should be sequential starting from 10
        orders = [mapping["order"] for mapping in result]
        assert orders == [10, 11, 12]
        assert next_order == 13

        # Verify teams are represented correctly
        teams = [mapping["team"] for mapping in result]
        assert "team1" in teams
        assert "team2" in teams
        assert "team3" in teams
        assert teams.count("team2") == 1  # team2 should appear once (consolidated)

    def test_team_with_auth_type_sso(self):
        """Test team mapping with auth_type='sso' (default behavior)."""
        team_map = {"testteam": {"organization": "testorg", "users": ["testuser"]}}

        result, _ = team_map_to_gateway_format(team_map, auth_type='sso')

        assert len(result) == 1
        mapping = result[0]
        assert mapping["name"] == "testorg - testteam U:1"
        assert mapping["triggers"]["attributes"]["username"]["equals"] == "testuser"

    def test_team_with_auth_type_ldap(self):
        """Test team mapping with auth_type='ldap'."""
        team_map = {"testteam": {"organization": "testorg", "users": ["admin_group"]}}

        result, _ = team_map_to_gateway_format(team_map, auth_type='ldap')

        assert len(result) == 1
        mapping = result[0]
        assert "Match User Groups" in mapping["name"]
        assert mapping["triggers"]["groups"]["has_or"] == ["admin_group"]

    def test_team_with_auth_type_ldap_boolean(self):
        """Test team mapping with auth_type='ldap' and boolean values."""
        team_map_true = {"testteam": {"organization": "testorg", "users": True}}
        team_map_false = {"testteam": {"organization": "testorg", "users": False}}

        result_true, _ = team_map_to_gateway_format(team_map_true, auth_type='ldap')
        result_false, _ = team_map_to_gateway_format(team_map_false, auth_type='ldap')

        assert len(result_true) == 1
        assert "Always Allow" in result_true[0]["name"]
        assert result_true[0]["triggers"]["always"] == {}

        assert len(result_false) == 1
        assert "Never Allow" in result_false[0]["name"]
        assert result_false[0]["triggers"]["never"] == {}


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
        {"org1": {"users": ["username1"]}},
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
        ({"team1": {"organization": "org1", "users": ["username1"]}}, 1),
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
        {"team1": {"organization": "org1", "users": ["username1"]}},
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


class TestAAP51531SpecificCase:
    """Test case specifically for JIRA AAP-51531 requirements."""

    def test_ldap_networking_org_mapping_aap_51531(self):
        """Test the specific LDAP organization mapping case for JIRA AAP-51531."""
        # This case is added for JIRA AAP-51531
        org_map = {"Networking": {"admins": "cn=networkadmins,ou=groups,dc=example,dc=com", "users": True, "remove_admins": True, "remove_users": True}}

        result = get_org_mappers(org_map, auth_type='ldap')

        # Should create 2 mappers: one for admins, one for users
        assert len(result) == 2

        # Find admin and user mappers
        admin_mapper = next((m for m in result if m['role'] == 'Organization Admin'), None)
        user_mapper = next((m for m in result if m['role'] == 'Organization Member'), None)

        assert admin_mapper is not None
        assert user_mapper is not None

        # Verify admin mapper details
        assert admin_mapper['organization'] == 'Networking'
        assert admin_mapper['revoke'] is True  # remove_admins: true
        assert 'Match User Groups' in admin_mapper['name']
        assert admin_mapper['triggers']['groups']['has_or'] == ['cn=networkadmins,ou=groups,dc=example,dc=com']

        # Verify user mapper details
        assert user_mapper['organization'] == 'Networking'
        assert user_mapper['revoke'] is True  # remove_users: true
        assert 'Always Allow' in user_mapper['name']
        assert user_mapper['triggers']['always'] == {}

        # Verify both mappers have correct map_type
        assert admin_mapper['map_type'] == 'organization'
        assert user_mapper['map_type'] == 'organization'
