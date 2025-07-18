import pytest
from unittest.mock import MagicMock
from awx.sso.utils.google_oauth2_migrator import GoogleOAuth2Migrator


@pytest.fixture
def test_google_config(settings):
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = "test_key"
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = "test_secret"
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_CALLBACK_URL = "https://tower.example.com/sso/complete/google-oauth2/"
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_ORGANIZATION_MAP = {"My Org": {"users": True}}
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_TEAM_MAP = {"My Team": {"organization": "My Org", "users": True}}
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE = ["profile", "email"]


@pytest.mark.django_db
def test_get_controller_config(test_google_config):
    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = GoogleOAuth2Migrator(gateway_client, command_obj)

    result = obj.get_controller_config()
    assert len(result) == 1
    config = result[0]
    assert config['category'] == 'Google OAuth2'
    settings = config['settings']
    assert settings['SOCIAL_AUTH_GOOGLE_OAUTH2_KEY'] == 'test_key'
    assert settings['SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET'] == 'test_secret'
    assert settings['SOCIAL_AUTH_GOOGLE_OAUTH2_CALLBACK_URL'] == "https://tower.example.com/sso/complete/google-oauth2/"
    assert settings['SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE'] == ["profile", "email"]
    # Assert that other settings are not present in the returned config
    assert 'SOCIAL_AUTH_GOOGLE_OAUTH2_ORGANIZATION_MAP' not in settings
    assert 'SOCIAL_AUTH_GOOGLE_OAUTH2_TEAM_MAP' not in settings


@pytest.mark.django_db
def test_create_gateway_authenticator(mocker, test_google_config):
    mocker.patch('django.conf.settings.LOGGING', {})

    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = GoogleOAuth2Migrator(gateway_client, command_obj)
    mock_submit = MagicMock(return_value=True)
    obj.submit_authenticator = mock_submit

    configs = obj.get_controller_config()
    result = obj.create_gateway_authenticator(configs[0])

    assert result is True
    mock_submit.assert_called_once()

    # Assert payload sent to gateway
    payload = mock_submit.call_args[0][0]
    assert payload['name'] == 'google'
    assert payload['slug'] == 'aap-google-oauth2-google-oauth2'
    assert payload['type'] == 'ansible_base.authentication.authenticator_plugins.google_oauth2'
    assert payload['enabled'] is True
    assert payload['create_objects'] is True
    assert payload['remove_users'] is False

    # Assert configuration details
    configuration = payload['configuration']
    assert configuration['KEY'] == 'test_key'
    assert configuration['SECRET'] == 'test_secret'
    assert configuration['CALLBACK_URL'] == 'https://tower.example.com/sso/complete/google-oauth2/'
    assert configuration['SCOPE'] == ['profile', 'email']

    # Assert mappers
    assert len(payload['mappers']) == 2
    assert payload['mappers'][0]['map_type'] == 'organization'
    assert payload['mappers'][1]['map_type'] == 'team'

    # Assert ignore_keys
    ignore_keys = mock_submit.call_args[0][1]
    assert ignore_keys == ["ACCESS_TOKEN_METHOD", "REVOKE_TOKEN_METHOD"]


@pytest.mark.django_db
def test_create_gateway_authenticator_no_optional_values(mocker, settings):
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = "test_key"
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = "test_secret"
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_ORGANIZATION_MAP = {}
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_TEAM_MAP = {}
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE = None
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_CALLBACK_URL = None

    mocker.patch('django.conf.settings.LOGGING', {})

    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = GoogleOAuth2Migrator(gateway_client, command_obj)
    mock_submit = MagicMock(return_value=True)
    obj.submit_authenticator = mock_submit

    configs = obj.get_controller_config()
    obj.create_gateway_authenticator(configs[0])

    payload = mock_submit.call_args[0][0]
    assert 'CALLBACK_URL' not in payload['configuration']
    assert 'SCOPE' not in payload['configuration']

    ignore_keys = mock_submit.call_args[0][1]
    assert 'CALLBACK_URL' in ignore_keys
    assert 'SCOPE' in ignore_keys
