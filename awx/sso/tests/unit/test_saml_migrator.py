import pytest
from unittest.mock import MagicMock
from awx.sso.utils.saml_migrator import SAMLMigrator


@pytest.mark.django_db
def test_get_controller_config(basic_saml_config):
    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = SAMLMigrator(gateway_client, command_obj)

    result = obj.get_controller_config()
    lines = result[0]['settings']['configuration']['IDP_X509_CERT'].splitlines()
    assert lines[0] == '-----BEGIN CERTIFICATE-----'
    assert lines[1] == "A" * 64
    assert lines[2] == "B" * 64
    assert lines[3] == "C" * 23
    assert lines[-1] == '-----END CERTIFICATE-----'


@pytest.mark.django_db
def test_get_controller_config_with_mapper(saml_config_user_flags_no_value):
    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = SAMLMigrator(gateway_client, command_obj)

    result = obj.get_controller_config()
    expected_maps = [
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'Default',
            'team': 'Administrators',
            'name': 'Team-Administrators-Default',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['internal:unix:domain:admins']}, 'join_condition': 'or'}},
            'order': 1,
        },
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'North America',
            'team': 'East Coast',
            'name': 'Team-East Coast-North America',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['East Coast']}, 'join_condition': 'or'}},
            'order': 2,
        },
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'North America',
            'team': 'developers',
            'name': 'Team-developers-North America',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['developers']}, 'join_condition': 'or'}},
            'order': 3,
        },
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'South America',
            'team': 'developers',
            'name': 'Team-developers-South America',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['developers']}, 'join_condition': 'or'}},
            'order': 4,
        },
        {
            'map_type': 'is_superuser',
            'role': None,
            'name': 'Role-is_superuser-attr',
            'organization': None,
            'team': None,
            'revoke': True,
            'order': 5,
            'authenticator': -1,
            'triggers': {'attributes': {'friends': {}, 'join_condition': 'or'}},
        },
        {
            'map_type': 'is_superuser',
            'role': None,
            'name': 'Role-is_superuser',
            'organization': None,
            'team': None,
            'revoke': True,
            'order': 6,
            'authenticator': -1,
            'triggers': {'attributes': {'Role': {'in': ['wilma']}, 'join_condition': 'or'}},
        },
    ]
    assert result[0]['team_mappers'] == expected_maps
    extra_data = result[0]['settings']['configuration']['EXTRA_DATA']
    assert ['Role', 'Role'] in extra_data
    assert ['friends', 'friends'] in extra_data
    assert ['group_name', 'group_name'] in extra_data


@pytest.mark.django_db
def test_get_controller_config_with_roles(basic_saml_config):
    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = SAMLMigrator(gateway_client, command_obj)

    result = obj.get_controller_config()

    expected_maps = [
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'Default',
            'team': 'Administrators',
            'name': 'Team-Administrators-Default',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['internal:unix:domain:admins']}, 'join_condition': 'or'}},
            'order': 1,
        },
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'North America',
            'team': 'East Coast',
            'name': 'Team-East Coast-North America',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['East Coast']}, 'join_condition': 'or'}},
            'order': 2,
        },
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'North America',
            'team': 'developers',
            'name': 'Team-developers-North America',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['developers']}, 'join_condition': 'or'}},
            'order': 3,
        },
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'South America',
            'team': 'developers',
            'name': 'Team-developers-South America',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['developers']}, 'join_condition': 'or'}},
            'order': 4,
        },
        {
            'map_type': 'is_superuser',
            'role': None,
            'name': 'Role-is_superuser-attr',
            'organization': None,
            'team': None,
            'revoke': False,
            'order': 5,
            'authenticator': -1,
            'triggers': {'attributes': {'friends': {'in': ['barney', 'fred']}, 'join_condition': 'or'}},
        },
        {
            'map_type': 'role',
            'role': 'Platform Auditor',
            'name': 'Role-Platform Auditor-attr',
            'organization': None,
            'team': None,
            'revoke': True,
            'order': 6,
            'authenticator': -1,
            'triggers': {'attributes': {'auditor': {'in': ['bamm-bamm']}, 'join_condition': 'or'}},
        },
        {
            'map_type': 'is_superuser',
            'role': None,
            'name': 'Role-is_superuser',
            'organization': None,
            'team': None,
            'revoke': False,
            'order': 7,
            'authenticator': -1,
            'triggers': {'attributes': {'Role': {'in': ['wilma']}, 'join_condition': 'or'}},
        },
        {
            'map_type': 'role',
            'role': 'Platform Auditor',
            'name': 'Role-Platform Auditor',
            'organization': None,
            'team': None,
            'revoke': True,
            'order': 8,
            'authenticator': -1,
            'triggers': {'attributes': {'Role': {'in': ['fred']}, 'join_condition': 'or'}},
        },
        {
            'map_type': 'organization',
            'role': 'Organization Member',
            'name': 'Role-Organization Member-attr',
            'organization': "{% for_attr_value('member-of') %}",
            'team': None,
            'revoke': True,
            'order': 9,
            'authenticator': -1,
            'triggers': {'attributes': {'member-of': {}, 'join_condition': 'or'}},
        },
        {
            'map_type': 'organization',
            'role': 'Organization Admin',
            'name': 'Role-Organization Admin-attr',
            'organization': "{% for_attr_value('admin-of') %}",
            'team': None,
            'revoke': False,
            'order': 10,
            'authenticator': -1,
            'triggers': {'attributes': {'admin-of': {}, 'join_condition': 'or'}},
        },
    ]

    assert result[0]['team_mappers'] == expected_maps
    extra_data = result[0]['settings']['configuration']['EXTRA_DATA']
    assert ['member-of', 'member-of'] in extra_data
    assert ['admin-of', 'admin-of'] in extra_data
    assert ['Role', 'Role'] in extra_data
    assert ['auditor', 'auditor'] in extra_data
    assert ['friends', 'friends'] in extra_data
    assert ['group_name', 'group_name'] in extra_data
