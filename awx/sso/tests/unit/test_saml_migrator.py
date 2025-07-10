import pytest
from unittest.mock import MagicMock
from awx.sso.utils.saml_migrator import SAMLMigrator


@pytest.mark.django_db
def test_get_controller_config(test_saml_config):
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
