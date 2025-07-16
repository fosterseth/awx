import pytest

from django.contrib.auth.models import User

from awx.sso.backends import TACACSPlusBackend
from awx.sso.models import UserEnterpriseAuth


@pytest.fixture
def tacacsplus_backend():
    return TACACSPlusBackend()


@pytest.fixture
def existing_normal_user():
    try:
        user = User.objects.get(username="alice")
    except User.DoesNotExist:
        user = User(username="alice", password="password")
        user.save()
    return user


@pytest.fixture
def existing_tacacsplus_user():
    try:
        user = User.objects.get(username="foo")
    except User.DoesNotExist:
        user = User(username="foo")
        user.set_unusable_password()
        user.save()
        enterprise_auth = UserEnterpriseAuth(user=user, provider='tacacs+')
        enterprise_auth.save()
    return user


@pytest.fixture
def test_radius_config(settings):
    settings.RADIUS_SERVER = '127.0.0.1'
    settings.RADIUS_PORT = 1812
    settings.RADIUS_SECRET = 'secret'


@pytest.fixture
def test_saml_config(settings):
    settings.SAML_SECURITY_CONFIG = {
        "wantNameId": True,
        "signMetadata": False,
        "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        "nameIdEncrypted": False,
        "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "authnRequestsSigned": False,
        "logoutRequestSigned": False,
        "wantNameIdEncrypted": False,
        "logoutResponseSigned": False,
        "wantAssertionsSigned": True,
        "requestedAuthnContext": False,
        "wantAssertionsEncrypted": False,
    }
    settings.SOCIAL_AUTH_SAML_ENABLED_IDPS = {
        "example": {
            "attr_email": "email",
            "attr_first_name": "first_name",
            "attr_last_name": "last_name",
            "attr_user_permanent_id": "username",
            "attr_username": "username",
            "entity_id": "https://www.example.com/realms/sample",
            "url": "https://www.example.com/realms/sample/protocol/saml",
            "x509cert": "A" * 64 + "B" * 64 + "C" * 23,
        }
    }


@pytest.fixture
def test_tacacs_config(settings):
    settings.TACACSPLUS_HOST = "tacacshost"
    settings.TACACSPLUS_PORT = 49
    settings.TACACSPLUS_SECRET = "secret"
    settings.TACACSPLUS_SESSION_TIMEOUT = 10
    settings.TACACSPLUS_AUTH_PROTOCOL = "pap"
    settings.TACACSPLUS_REM_ADDR = True
