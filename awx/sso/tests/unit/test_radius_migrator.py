import pytest
from unittest.mock import MagicMock
from awx.sso.utils.radius_migrator import RADIUSMigrator


@pytest.mark.django_db
def test_get_controller_config(test_radius_config):
    gateway_client = MagicMock()
    command_obj = MagicMock()
    obj = RADIUSMigrator(gateway_client, command_obj)

    result = obj.get_controller_config()
    config = result[0]['settings']['configuration']
    assert config['SERVER'] == '127.0.0.1'
    assert config['PORT'] == 1812
    assert config['SECRET'] == 'secret'
    assert len(config) == 3
