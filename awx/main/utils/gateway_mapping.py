"""
Gateway mapping conversion utilities.

This module contains functions to convert AWX authentication mappings
(organization and team mappings) to AAP Gateway format.
"""

import re
from typing import cast, Any, Literal, Pattern, Union

email_regex = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def truncate_name(name: str, max_length: int = 128) -> str:
    """Truncate a name to the specified maximum length."""
    if len(name) <= max_length:
        return name
    return name[:max_length]


def build_truncated_name(org_name: str, entity_name: str, trigger_name: str, max_component_length: int = 40) -> str:
    """Build a name by truncating each component individually and joining with ' - '."""
    truncated_org = truncate_name(org_name, max_component_length)
    truncated_entity = truncate_name(entity_name, max_component_length)
    truncated_trigger = truncate_name(trigger_name, max_component_length)
    return f"{truncated_org} - {truncated_entity} {truncated_trigger}"


def pattern_to_slash_format(pattern: Any) -> str:
    """Convert a re.Pattern object to /pattern/flags format."""
    if not isinstance(pattern, re.Pattern):
        return str(pattern)

    flags_str = ""
    if pattern.flags & re.IGNORECASE:
        flags_str += "i"
    if pattern.flags & re.MULTILINE:
        flags_str += "m"
    if pattern.flags & re.DOTALL:
        flags_str += "s"
    if pattern.flags & re.VERBOSE:
        flags_str += "x"

    return f"/{pattern.pattern}/{flags_str}"


def process_ldap_user_list(
    groups: Union[None, str, bool, list[Union[None, str, bool]]],
) -> list[dict[str, Any]]:
    if not isinstance(groups, list):
        groups = [groups]

    # Type cast to help mypy understand the type after conversion
    groups_list: list[Union[str, bool, None]] = cast(list[Union[str, bool, None]], groups)

    triggers = []
    if groups_list == [None]:
        # A None value means we shouldn't update whatever this is based on LDAP values
        pass
    elif groups_list == []:
        # Empty list means no triggers should be created
        pass
    elif groups_list == [True]:
        triggers.append({"name": "Always Allow", "trigger": {"always": {}}})
    elif groups_list == [False]:
        triggers.append(
            {
                "name": "Never Allow",
                "trigger": {"never": {}},
            }
        )
    else:
        triggers.append({"name": "Match User Groups", "trigger": {"groups": {"has_or": groups_list}}})
    return triggers


def process_sso_user_list(
    users: Union[str, bool, Pattern[str], list[Union[str, bool, Pattern[str]]]], email_attr: str = 'email', username_attr: str = 'username'
) -> dict[str, Union[str, dict[str, dict[str, Union[str, list[str]]]]]]:
    """Process SSO user list and return a single consolidated trigger instead of multiple separate ones."""
    if not isinstance(users, list):
        users = [users]

    # Type cast to help mypy understand the type after conversion
    user_list: list[Union[str, bool, Pattern[str]]] = cast(list[Union[str, bool, Pattern[str]]], users)

    if user_list == ["false"] or user_list == [False]:
        return {"name": "Never Allow", "trigger": {"never": {}}}
    elif user_list == ["true"] or user_list == [True]:
        return {"name": "Always Allow", "trigger": {"always": {}}}
    else:
        # Group users by type
        emails = []
        usernames = []
        regexes_username = []
        regexes_email = []

        for user_or_email in user_list:
            if isinstance(user_or_email, re.Pattern):
                pattern_str = pattern_to_slash_format(user_or_email)
                regexes_username.append(pattern_str)
                regexes_email.append(pattern_str)
            elif isinstance(user_or_email, str):
                if email_regex.match(user_or_email):
                    emails.append(user_or_email)
                else:
                    usernames.append(user_or_email)
            else:
                # Convert other objects to string and treat as both
                str_val = str(user_or_email)
                usernames.append(str_val)
                emails.append(str_val)

        # Build consolidated trigger
        attributes = {"join_condition": "or"}

        if emails:
            if len(emails) == 1:
                attributes[email_attr] = {"equals": emails[0]}
            else:
                attributes[email_attr] = {"in": emails}

        if usernames:
            if len(usernames) == 1:
                attributes[username_attr] = {"equals": usernames[0]}
            else:
                attributes[username_attr] = {"in": usernames}

        # For regex patterns, we need to create separate matches conditions since there's no matches_or
        for i, pattern in enumerate(regexes_username):
            pattern_key = f"{username_attr}_pattern_{i}" if len(regexes_username) > 1 else username_attr
            if pattern_key not in attributes:
                attributes[pattern_key] = {}
            attributes[pattern_key]["matches"] = pattern

        for i, pattern in enumerate(regexes_email):
            pattern_key = f"{email_attr}_pattern_{i}" if len(regexes_email) > 1 else email_attr
            if pattern_key not in attributes:
                attributes[pattern_key] = {}
            attributes[pattern_key]["matches"] = pattern

        # Create a deterministic, concise name based on trigger types and counts
        name_parts = []
        if emails:
            name_parts.append(f"E:{len(emails)}")
        if usernames:
            name_parts.append(f"U:{len(usernames)}")
        if regexes_username:
            name_parts.append(f"UP:{len(regexes_username)}")
        if regexes_email:
            name_parts.append(f"EP:{len(regexes_email)}")

        name = " ".join(name_parts) if name_parts else "Mixed Rules"

        return {"name": name, "trigger": {"attributes": attributes}}


def team_map_to_gateway_format(team_map, start_order=1, email_attr: str = 'email', username_attr: str = 'username', auth_type: Literal['sso', 'ldap'] = 'sso'):
    """Convert AWX team mapping to Gateway authenticator format.

    Args:
        team_map: The SOCIAL_AUTH_*_TEAM_MAP setting value
        start_order: Starting order value for the mappers
        email_attr: The attribute representing the email
        username_attr: The attribute representing the username

    Returns:
        tuple: (List of Gateway-compatible team mappers, next_order)
    """
    if team_map is None:
        return [], start_order

    result = []
    order = start_order

    for team_name in team_map.keys():
        team = team_map[team_name]
        # TODO: Confirm that if we have None with remove we still won't remove
        if team['users'] is None:
            continue

        # Get the organization name
        organization_name = team.get('organization', 'Unknown')

        # Check for remove flag
        revoke = team.get('remove', False)

        if auth_type == 'ldap':
            triggers = process_ldap_user_list(team['users'])
            for trigger in triggers:
                result.append(
                    {
                        "name": build_truncated_name(organization_name, team_name, trigger['name']),
                        "map_type": "team",
                        "order": order,
                        "authenticator": -1,  # Will be updated when creating the mapper
                        "triggers": trigger['trigger'],
                        "organization": organization_name,
                        "team": team_name,
                        "role": "Team Member",  # Gateway team member role
                        "revoke": revoke,
                    }
                )
                order += 1

        if auth_type == 'sso':
            trigger = process_sso_user_list(team['users'], email_attr=email_attr, username_attr=username_attr)
            result.append(
                {
                    "name": build_truncated_name(organization_name, team_name, trigger['name']),
                    "map_type": "team",
                    "order": order,
                    "authenticator": -1,  # Will be updated when creating the mapper
                    "triggers": trigger['trigger'],
                    "organization": organization_name,
                    "team": team_name,
                    "role": "Team Member",  # Gateway team member role
                    "revoke": revoke,
                }
            )
            order += 1

    return result, order


def org_map_to_gateway_format(org_map, start_order=1, email_attr: str = 'email', username_attr: str = 'username', auth_type: Literal['sso', 'ldap'] = 'sso'):
    """Convert AWX organization mapping to Gateway authenticator format.

    Args:
        org_map: The SOCIAL_AUTH_*_ORGANIZATION_MAP setting value
        start_order: Starting order value for the mappers
        email_attr: The attribute representing the email
        username_attr: The attribute representing the username

    Returns:
        tuple: (List of Gateway-compatible organization mappers, next_order)
    """
    if org_map is None:
        return [], start_order

    result = []
    order = start_order

    for organization_name in org_map.keys():
        organization = org_map[organization_name]
        for user_type in ['admins', 'users']:
            if organization.get(user_type, None) is None:
                # TODO: Confirm that if we have None with remove we still won't remove
                continue

            # Get the permission type
            permission_type = user_type.title()

            # Map AWX admin/users to appropriate Gateway organization roles
            role = "Organization Admin" if user_type == "admins" else "Organization Member"

            # Check for remove flags
            revoke = False
            if organization.get(f"remove_{user_type}"):
                revoke = True

            if auth_type == 'ldap':
                triggers = process_ldap_user_list(organization[user_type])
                for trigger in triggers:
                    result.append(
                        {
                            "name": build_truncated_name(organization_name, permission_type, trigger['name']),
                            "map_type": "organization",
                            "order": order,
                            "authenticator": -1,  # Will be updated when creating the mapper
                            "triggers": trigger['trigger'],
                            "organization": organization_name,
                            "team": None,  # Organization-level mapping, not team-specific
                            "role": role,
                            "revoke": revoke,
                        }
                    )
                    order += 1

            if auth_type == 'sso':
                trigger = process_sso_user_list(organization[user_type], email_attr=email_attr, username_attr=username_attr)
                result.append(
                    {
                        "name": build_truncated_name(organization_name, permission_type, trigger['name']),
                        "map_type": "organization",
                        "order": order,
                        "authenticator": -1,  # Will be updated when creating the mapper
                        "triggers": trigger['trigger'],
                        "organization": organization_name,
                        "team": None,  # Organization-level mapping, not team-specific
                        "role": role,
                        "revoke": revoke,
                    }
                )
                order += 1

    return result, order


def role_map_to_gateway_format(role_map, start_order=1):
    """Convert AWX role mapping to Gateway authenticator format.

    Args:
        role_map: An LDAP or SAML role mapping
        start_order: Starting order value for the mappers

    Returns:
        tuple: (List of Gateway-compatible organization mappers, next_order)
    """
    if role_map is None:
        return [], start_order

    result = []
    order = start_order

    for flag in role_map:
        groups = role_map[flag]
        if type(groups) is str:
            groups = [groups]

        if flag == 'is_superuser':
            # Gateway has a special map_type for superusers
            result.append(
                {
                    "name": f"{flag} - role",
                    "authenticator": -1,
                    "revoke": True,
                    "map_type": flag,
                    "team": None,
                    "organization": None,
                    "triggers": {
                        "groups": {
                            "has_or": groups,
                        }
                    },
                    "order": order,
                }
            )
        elif flag == 'is_system_auditor':
            # roles other than superuser must be represented as a generic role mapper
            result.append(
                {
                    "name": f"{flag} - role",
                    "authenticator": -1,
                    "revoke": True,
                    "map_type": "role",
                    "role": "Platform Auditor",
                    "team": None,
                    "organization": None,
                    "triggers": {
                        "groups": {
                            "has_or": groups,
                        }
                    },
                    "order": order,
                }
            )

        order += 1

    return result, order
