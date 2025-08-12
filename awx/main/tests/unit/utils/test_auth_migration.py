"""
Unit tests for auth migration utilities.
"""

import pytest
import re
from awx.main.utils.gateway_mapping import org_map_to_gateway_format, team_map_to_gateway_format, role_map_to_gateway_format, process_sso_user_list


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


class TestProcessSSOUserList:
    """Tests for the process_sso_user_list function."""

    def test_false_boolean(self):
        """Test that False creates 'Never Allow' trigger."""
        result = process_sso_user_list(False)

        assert len(result) == 1
        assert result[0]["name"] == "Never Allow"
        assert result[0]["trigger"] == {"never": {}}

    def test_true_boolean(self):
        """Test that True creates 'Always Allow' trigger."""
        result = process_sso_user_list(True)

        assert len(result) == 1
        assert result[0]["name"] == "Always Allow"
        assert result[0]["trigger"] == {"always": {}}

    def test_false_string_list(self):
        """Test that ['false'] creates 'Never Allow' trigger."""
        result = process_sso_user_list(["false"])

        assert len(result) == 1
        assert result[0]["name"] == "Never Allow"
        assert result[0]["trigger"] == {"never": {}}

    def test_true_string_list(self):
        """Test that ['true'] creates 'Always Allow' trigger."""
        result = process_sso_user_list(["true"])

        assert len(result) == 1
        assert result[0]["name"] == "Always Allow"
        assert result[0]["trigger"] == {"always": {}}

    def test_string_user_list(self):
        """Test that regular string users are processed correctly."""
        result = process_sso_user_list(["testuser"])

        assert len(result) == 1
        assert result[0]["name"] == "Username equals testuser"
        assert result[0]["trigger"]["attributes"]["username"]["equals"] == "testuser"

    def test_email_user_list(self):
        """Test that email addresses are processed correctly."""
        result = process_sso_user_list(["test@example.com"])

        assert len(result) == 1
        assert result[0]["name"] == "Email Equals test@example.com"
        assert result[0]["trigger"]["attributes"]["email"]["equals"] == "test@example.com"

    def test_mixed_string_list(self):
        """Test that mixed list with 'true', 'false', and regular users works correctly."""
        result = process_sso_user_list(["true", "testuser", "false"])

        # Should process each item separately, not treat the whole list as true/false
        assert len(result) == 3

        # Check each result
        names = [r["name"] for r in result]
        assert "Username equals true" in names
        assert "Username equals testuser" in names
        assert "Username equals false" in names

    def test_custom_email_username_attrs(self):
        """Test that custom email and username attributes work correctly."""
        result = process_sso_user_list(["test@example.com"], email_attr='custom_email', username_attr='custom_username')

        assert len(result) == 1
        assert result[0]["trigger"]["attributes"]["custom_email"]["equals"] == "test@example.com"

    def test_regex_pattern(self):
        """Test that regex patterns create both username and email matches."""
        pattern = re.compile(r"^admin.*@example\.com$")
        result = process_sso_user_list([pattern])

        assert len(result) == 2
        assert "Match Username" in result[0]["name"]
        assert "Match Email" in result[1]["name"]
        assert result[0]["trigger"]["attributes"]["username"]["matches"] == "/^admin.*@example\\.com$/"
        assert result[1]["trigger"]["attributes"]["email"]["matches"] == "/^admin.*@example\\.com$/"


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
        assert mapping["name"] == "myorg - Admins Username equals admin-username"
        assert mapping["triggers"] == {"attributes": {"join_condition": "or", "username": {"equals": "admin-username"}}}
        assert mapping["role"] == "Organization Admin"

    def test_org_with_admin_list(self):
        """Test organization with admin access set to multiple groups."""
        org_map = {"myorg": {"admins": ["admin-username1", "admin-username2"]}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 2
        assert result[0]["name"] == "myorg - Admins Username equals admin-username1"
        assert result[1]["name"] == "myorg - Admins Username equals admin-username2"
        assert result[0]["order"] == 1
        assert result[1]["order"] == 2

    def test_org_with_email_detection(self):
        """Test that email addresses are correctly identified and handled."""
        org_map = {"myorg": {"users": ["user@example.com", "admin@test.org", "not-an-email"]}}

        result, _ = org_map_to_gateway_format(org_map)

        assert len(result) == 3

        # First mapping should be for email
        email_mapping = result[0]
        assert "user@example.com" in email_mapping["name"]
        assert "Email Equals" in email_mapping["name"]
        assert email_mapping["triggers"]["attributes"]["email"]["equals"] == "user@example.com"

        # Second mapping should be for email
        email_mapping2 = result[1]
        assert "admin@test.org" in email_mapping2["name"]
        assert "Email Equals" in email_mapping2["name"]
        assert email_mapping2["triggers"]["attributes"]["email"]["equals"] == "admin@test.org"

        # Third mapping should be for username (not email)
        username_mapping = result[2]
        assert "not-an-email" in username_mapping["name"]
        assert "Username equals" in username_mapping["name"]
        assert username_mapping["triggers"]["attributes"]["username"]["equals"] == "not-an-email"

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

        # Should create 2 mappings - one for username match, one for email match
        assert len(result) == 2, f"Expected 2 items but got: {result}"

        username_mapping = result[0]
        assert "Match Username" in username_mapping["name"]
        assert username_mapping["triggers"]["attributes"]["username"]["matches"] == f"/{regex_str}/"

        email_mapping = result[1]
        assert "Match Email" in email_mapping["name"]
        assert email_mapping["triggers"]["attributes"]["email"]["matches"] == f"/{regex_str}/"

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

        # Should have 3 mappings total
        assert len(result) == 3
        assert result[0]["order"] == 10
        assert result[1]["order"] == 11
        assert result[2]["order"] == 12
        assert next_order == 13

    def test_org_comprehensive_field_validation(self):
        """Test comprehensive validation of all fields in org mappings."""
        org_map = {"test-org": {"admins": ["test-admin"], "remove_admins": False}}

        result, next_order = org_map_to_gateway_format(org_map, start_order=5)

        assert len(result) == 1
        mapping = result[0]

        # Validate all required fields and their types
        assert isinstance(mapping["name"], str)
        assert mapping["name"] == "test-org - Admins Username equals test-admin"

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

        # Test with multiple mappings from single org
        org_map = {"multi": {"users": ["user1", "user2"]}}
        result, next_order = org_map_to_gateway_format(org_map)
        assert len(result) == 2
        assert next_order == 3


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

        # Should have 3 mappings - one for each user
        assert len(result) == 3

        # First mapping should be for email (emails are detected and use email attribute)
        email_mapping = result[0]
        assert "user@example.com" in email_mapping["name"]
        assert "Email Equals" in email_mapping["name"]
        assert email_mapping["triggers"]["attributes"]["email"]["equals"] == "user@example.com"

        # Second mapping should be for email
        email_mapping2 = result[1]
        assert "admin@test.org" in email_mapping2["name"]
        assert "Email Equals" in email_mapping2["name"]
        assert email_mapping2["triggers"]["attributes"]["email"]["equals"] == "admin@test.org"

        # Third mapping should be for username (not email)
        username_mapping = result[2]
        assert "not-an-email" in username_mapping["name"]
        assert "Username equals" in username_mapping["name"]
        assert username_mapping["triggers"]["attributes"]["username"]["equals"] == "not-an-email"

    def test_team_with_custom_email_username_attrs(self):
        """Test team mapping with custom email and username attributes."""
        team_map = {"custom-team": {"organization": "myorg", "users": ["test@example.com"]}}

        result, _ = team_map_to_gateway_format(team_map, email_attr='custom_email', username_attr='custom_username')

        assert len(result) == 1
        mapping = result[0]
        assert mapping["triggers"]["attributes"]["custom_email"]["equals"] == "test@example.com"
        assert "Email Equals" in mapping["name"]

    def test_team_with_regex_pattern_objects(self):
        """Test team mapping with actual re.Pattern objects."""
        regex_str = "^admin.*@example\\.com$"

        team_map = {"regex-team": {"organization": "myorg", "users": [re.compile(regex_str)]}}

        result, _ = team_map_to_gateway_format(team_map)

        # Should create 2 mappings - one for username match, one for email match
        assert len(result) == 2, f"Expected 2 items but got: {result}"

        username_mapping = result[0]
        assert "Match Username" in username_mapping["name"]
        assert username_mapping["triggers"]["attributes"]["username"]["matches"] == f"/{regex_str}/"

        email_mapping = result[1]
        assert "Match Email" in email_mapping["name"]
        assert email_mapping["triggers"]["attributes"]["email"]["matches"] == f"/{regex_str}/"

    def test_team_with_non_string_objects(self):
        """Test team mapping with non-string objects that get converted."""

        class CustomObject:
            def __str__(self):
                return "custom_object_string"

        custom_obj = CustomObject()
        team_map = {"object-team": {"organization": "myorg", "users": [custom_obj, 12345]}}

        result, _ = team_map_to_gateway_format(team_map)

        # Should create 4 mappings - 2 for custom object (username + email), 2 for number
        assert len(result) == 4

        # Check custom object mappings - non-string objects create both username and email mappings
        custom_mappings = [r for r in result if "custom_object_string" in r["name"]]
        assert len(custom_mappings) == 2

        # Check number mappings - numbers also create both username and email mappings
        number_mappings = [r for r in result if "12345" in r["name"]]
        assert len(number_mappings) == 2

    def test_team_with_mixed_data_types(self):
        """Test team mapping with mixed data types in users list."""
        regex_str = 'test.*'

        team_map = {"mixed-team": {"organization": "myorg", "users": ["string_user", "email@test.com", re.compile(regex_str), 999, True]}}

        result, _ = team_map_to_gateway_format(team_map)

        # Should handle all different types appropriately
        assert len(result) > 0

        # Verify that each type is handled
        names = [mapping["name"] for mapping in result]
        assert any("string_user" in name for name in names), f"Expected to find string_user in {(', '.join(names))}"
        assert any("email@test.com" in name for name in names), f"Expected to find email@test.com in {(', '.join(names))}"
        assert any("999" in name for name in names), f"Expected to find 999 in {(', '.join(names))}"
        assert any("True" in name for name in names), f"Expected to find True in {(', '.join(names))}"

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
        assert "Username equals" in empty_team_mapping["name"]
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

        assert len(result) == 2

        # Verify special characters are preserved in names
        for mapping in result:
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

        assert len(result) == 2

        # Verify unicode characters are handled correctly
        for mapping in result:
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

        # Test with multiple mappings from single team
        team_map = {"multi": {"organization": "org", "users": ["user1", "user2"]}}
        result, next_order = team_map_to_gateway_format(team_map)
        assert len(result) == 2
        assert next_order == 3

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

        # Should create 500 mappings (100 teams * 5 users each)
        assert len(result) == 500

        # Verify orders are sequential
        orders = [mapping["order"] for mapping in result]
        assert orders == list(range(1, 501))
        assert next_order == 501

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

                # The attribute should have either "equals" or "matches"
                for attr_name in ["username", "email"]:
                    if attr_name in attrs:
                        attr_value = attrs[attr_name]
                        assert ("equals" in attr_value) or ("matches" in attr_value)

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
        assert "Username equals" in mapping["name"]
        assert mapping["triggers"]["attributes"]["username"]["equals"] == "/^admin.*@example\\.com$/"

    def test_team_comprehensive_field_validation(self):
        """Test comprehensive validation of all fields in team mappings."""
        team_map = {"comprehensive-team": {"organization": "test-org", "users": ["test-user"], "remove": False}}

        result, next_order = team_map_to_gateway_format(team_map, start_order=5)

        assert len(result) == 1
        mapping = result[0]

        # Validate all required fields and their types
        assert isinstance(mapping["name"], str)
        assert mapping["name"] == "test-org - comprehensive-team Username equals test-user"

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
            "team2": {"organization": "org2", "users": ["user1", "user2"]},  # 2 mappings
            "team3": {"organization": "org3", "users": False},  # 1 mapping
        }

        result, next_order = team_map_to_gateway_format(team_map, start_order=10)

        # Should have 4 total mappings
        assert len(result) == 4

        # Orders should be sequential starting from 10
        orders = [mapping["order"] for mapping in result]
        assert orders == [10, 11, 12, 13]
        assert next_order == 14

        # Verify teams are represented correctly
        teams = [mapping["team"] for mapping in result]
        assert "team1" in teams
        assert "team2" in teams
        assert "team3" in teams
        assert teams.count("team2") == 2  # team2 should appear twice


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
