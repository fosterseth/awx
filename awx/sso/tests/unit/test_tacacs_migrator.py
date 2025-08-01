import pytest
from unittest.mock import MagicMock
from awx.sso.utils.tacacs_migrator import TACACSMigrator


@pytest.mark.django_db
def test_get_controller_config(test_tacacs_config):
    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = TACACSMigrator(gateway_client, command_obj)

    result = obj.get_controller_config()
    assert len(result) == 1
    config = result[0]
    assert config['category'] == 'TACACSPLUS'
    settings_data = config['settings']
    assert settings_data['name'] == 'default'
    assert settings_data['type'] == 'ansible_base.authentication.authenticator_plugins.tacacs'

    configuration = settings_data['configuration']
    assert configuration['HOST'] == 'tacacshost'
    assert configuration['PORT'] == 49
    assert configuration['SECRET'] == 'secret'
    assert configuration['SESSION_TIMEOUT'] == 10
    assert configuration['AUTH_PROTOCOL'] == 'pap'
    assert configuration['REM_ADDR'] is True


@pytest.mark.django_db
def test_get_controller_config_no_host(settings):
    settings.TACACSPLUS_HOST = ""
    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = TACACSMigrator(gateway_client, command_obj)

    result = obj.get_controller_config()
    assert len(result) == 0
