import pytest
from unittest.mock import MagicMock, patch
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
            'name': 'Role-is_superuser',
            'organization': None,
            'team': None,
            'revoke': True,
            'order': 5,
            'authenticator': -1,
            'triggers': {'attributes': {'Role': {'in': ['wilma']}, 'join_condition': 'or'}},
        },
        {
            'map_type': 'is_superuser',
            'role': None,
            'name': 'Role-is_superuser-attr',
            'organization': None,
            'team': None,
            'revoke': True,
            'order': 6,
            'authenticator': -1,
            'triggers': {'attributes': {'friends': {}, 'join_condition': 'or'}},
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
            'name': 'Role-is_superuser',
            'organization': None,
            'team': None,
            'revoke': False,
            'order': 5,
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
            'order': 6,
            'authenticator': -1,
            'triggers': {'attributes': {'Role': {'in': ['fred']}, 'join_condition': 'or'}},
        },
        {
            'map_type': 'is_superuser',
            'role': None,
            'name': 'Role-is_superuser-attr',
            'organization': None,
            'team': None,
            'revoke': False,
            'order': 7,
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
            'order': 8,
            'authenticator': -1,
            'triggers': {'attributes': {'auditor': {'in': ['bamm-bamm']}, 'join_condition': 'or'}},
        },
        {
            'map_type': 'organization',
            'role': 'Organization Member',
            'name': 'Role-Organization Member-attr',
            'organization': "{% for_attr_value(member-of) %}",
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
            'organization': "{% for_attr_value(admin-of) %}",
            'team': None,
            'revoke': False,
            'order': 10,
            'authenticator': -1,
            'triggers': {'attributes': {'admin-of': {}, 'join_condition': 'or'}},
        },
    ]

    assert result[0]['team_mappers'] == expected_maps
    extra_data = result[0]['settings']['configuration']['EXTRA_DATA']
    extra_data_items = [
        ['member-of', 'member-of'],
        ['admin-of', 'admin-of'],
        ['Role', 'Role'],
        ['friends', 'friends'],
        ['group_name', 'group_name'],
    ]
    for item in extra_data_items:
        assert item in extra_data
        assert extra_data.count(item) == 1


@pytest.mark.django_db
def test_get_controller_config_enabled_false(basic_saml_config):
    """SAML controller export marks settings.enabled False by default."""
    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = SAMLMigrator(gateway_client, command_obj)

    result = obj.get_controller_config()
    assert isinstance(result, list) and len(result) >= 1
    assert result[0]['settings']['enabled'] is False


@pytest.mark.django_db
def test_team_attr_collapses_duplicate_team_org_map_rows(settings):
    """
    A 2.4 SAML team_org_map can repeat the same (team_alias, organization)
    pair across rows when several IdP group values should grant the same
    AAP team. Each row produces a Gateway mapper whose name is derived from
    (team_alias, organization), so duplicates collide on the gateway's
    uniqueness constraint and earlier code silently lost all but the first.

    The migrator now folds those rows into a single mapper whose trigger's
    `in` list contains every matching value, deduplicated and order-preserving.
    """
    settings.SAML_SECURITY_CONFIG = {"requestedAuthnContext": False}
    settings.SOCIAL_AUTH_SAML_ENABLED_IDPS = {
        "example": {
            "attr_email": "email",
            "attr_first_name": "first_name",
            "attr_last_name": "last_name",
            "attr_user_permanent_id": "username",
            "attr_username": "username",
            "entity_id": "https://www.example.com/realms/sample",
            "url": "https://www.example.com/realms/sample/protocol/saml",
            "x509cert": "A" * 64,
        }
    }
    settings.SOCIAL_AUTH_SAML_TEAM_ATTR = {
        "remove": False,
        "saml_attr": "group_name",
        "team_org_map": [
            # Single-row pair: should produce one mapper with one value.
            {"team": "grp-solo", "team_alias": "solo", "organization": "OrgA"},
            # Three rows sharing (team_alias, organization): should fold into
            # ONE mapper with all three values in `in`, preserving input order.
            {"team": "grp-1", "team_alias": "engineers", "organization": "Engineering"},
            {"team": "grp-2", "team_alias": "engineers", "organization": "Engineering"},
            {"team": "grp-3", "team_alias": "engineers", "organization": "Engineering"},
            # List-valued `team` (the pre-collapsed input shape some operators use):
            # values flow through unchanged into the same single mapper.
            {"team": ["grp-list-1", "grp-list-2"], "team_alias": "list_team", "organization": "OrgB"},
            # Two rows with the same value: should appear only once in `in`.
            {"team": "grp-dup", "team_alias": "dupe_team", "organization": "OrgC"},
            {"team": "grp-dup", "team_alias": "dupe_team", "organization": "OrgC"},
        ],
    }

    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = SAMLMigrator(gateway_client, command_obj)

    result = obj.get_controller_config()
    team_mappers = result[0]['team_mappers']

    expected = [
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'OrgA',
            'team': 'solo',
            'name': 'Team-solo-OrgA',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['grp-solo']}, 'join_condition': 'or'}},
            'order': 1,
        },
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'Engineering',
            'team': 'engineers',
            'name': 'Team-engineers-Engineering',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['grp-1', 'grp-2', 'grp-3']}, 'join_condition': 'or'}},
            'order': 2,
        },
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'OrgB',
            'team': 'list_team',
            'name': 'Team-list_team-OrgB',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['grp-list-1', 'grp-list-2']}, 'join_condition': 'or'}},
            'order': 3,
        },
        {
            'map_type': 'team',
            'role': 'Team Member',
            'organization': 'OrgC',
            'team': 'dupe_team',
            'name': 'Team-dupe_team-OrgC',
            'revoke': False,
            'authenticator': -1,
            'triggers': {'attributes': {'group_name': {'in': ['grp-dup']}, 'join_condition': 'or'}},
            'order': 4,
        },
    ]
    assert team_mappers == expected

    # Mapper names must be unique - the original bug was driven by collisions here.
    names = [m['name'] for m in team_mappers]
    assert len(names) == len(set(names))


@pytest.mark.django_db
def test_create_gateway_authenticator_submits_disabled(basic_saml_config):
    """Submitted Gateway authenticator config must have enabled=False and correct ignore keys."""
    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = SAMLMigrator(gateway_client, command_obj)

    config = obj.get_controller_config()[0]

    with patch.object(
        obj,
        'submit_authenticator',
        return_value={'success': True, 'action': 'created', 'error': None},
    ) as submit_mock:
        obj.create_gateway_authenticator(config)

        # Extract submitted args: gateway_config, ignore_keys, original_config
        submitted_gateway_config = submit_mock.call_args[0][0]
        ignore_keys = submit_mock.call_args[0][1]

        assert submitted_gateway_config['enabled'] is False
        assert 'CALLBACK_URL' in ignore_keys
        assert 'SP_PRIVATE_KEY' in ignore_keys
