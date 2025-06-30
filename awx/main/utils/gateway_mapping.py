"""
Gateway mapping conversion utilities.

This module contains functions to convert AWX authentication mappings
(organization and team mappings) to AAP Gateway format.
"""


def team_map_to_gateway_format(team_map, start_order=1):
    """Convert AWX team mapping to Gateway authenticator format.

    Args:
        team_map: The SOCIAL_AUTH_*_TEAM_MAP setting value
        start_order: Starting order value for the mappers

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

        if team['users'] is False:
            triggers = {"never": {}}
        elif team['users'] is True:
            triggers = {"always": {}}
        else:
            import re

            # Handle the case where the value itself is a regex pattern
            if isinstance(team['users'], re.Pattern):
                # Convert single regex pattern to string in a list
                triggers = {"groups": {"has_or": [str(team['users'])]}}
            else:
                # Handle list or string values
                if type(team['users']) is str:
                    team['users'] = [team['users']]

                # Convert any non-string items to strings (e.g., regex patterns)
                users_list = []
                for user in team['users']:
                    if isinstance(user, str):
                        users_list.append(user)
                    elif isinstance(user, re.Pattern):
                        # Convert regex patterns to string representation
                        users_list.append(str(user.pattern))
                    else:
                        # Convert other objects to string representation
                        users_list.append(str(user))

                triggers = {"groups": {"has_or": users_list}}

        organization_name = team.get('organization', 'Unknown')
        # Check for remove flag
        revoke = team.get('remove', False)

        result.append(
            {
                "name": f"{organization_name} - {team_name}",
                "map_type": "team",
                "order": order,
                "authenticator": -1,  # Will be updated when creating the mapper
                "triggers": triggers,
                "organization": organization_name,
                "team": team_name,
                "role": "Team Member",  # Gateway team member role
                "revoke": revoke,
            }
        )

        order += 1

    return result, order


def org_map_to_gateway_format(org_map, start_order=1):
    """Convert AWX organization mapping to Gateway authenticator format.

    Args:
        org_map: The SOCIAL_AUTH_*_ORGANIZATION_MAP setting value
        start_order: Starting order value for the mappers

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
            if user_type in organization:
                # TODO: Confirm that if we have None with remove we still won't remove
                if organization[user_type] is None:
                    continue

                if organization[user_type] is False:
                    triggers = {"never": {}}
                elif organization[user_type] is True:
                    triggers = {"always": {}}
                else:
                    import re

                    # Handle the case where the value itself is a regex pattern
                    if isinstance(organization[user_type], re.Pattern):
                        # Convert single regex pattern to string in a list
                        triggers = {"groups": {"has_or": [str(organization[user_type])]}}
                    else:
                        # Handle list or string values
                        if type(organization[user_type]) is str:
                            organization[user_type] = [organization[user_type]]

                        # Convert any non-string items to strings (e.g., regex patterns)
                        users_list = []
                        for user in organization[user_type]:
                            if isinstance(user, str):
                                users_list.append(user)
                            elif isinstance(user, re.Pattern):
                                # Convert regex patterns to string representation
                                users_list.append(str(user.pattern))
                            else:
                                # Convert other objects to string representation
                                users_list.append(str(user))

                        triggers = {"groups": {"has_or": users_list}}

                team_name = f"Organization {user_type.title()}"
                # Map AWX admin/users to appropriate Gateway organization roles
                role = "Organization Admin" if user_type == "admins" else "Organization Member"

                # Check for remove flags
                revoke = False
                if user_type == "admins" and organization.get("remove_admins"):
                    revoke = True
                elif user_type == "users" and organization.get("remove_users"):
                    revoke = True

                result.append(
                    {
                        "name": f"{organization_name} - {team_name}",
                        "map_type": "organization",
                        "order": order,
                        "authenticator": -1,  # Will be updated when creating the mapper
                        "triggers": triggers,
                        "organization": organization_name,
                        "team": None,  # Organization-level mapping, not team-specific
                        "role": role,
                        "revoke": revoke,
                    }
                )

                order += 1

    return result, order
