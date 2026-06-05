import pytest


@pytest.fixture
def mock_setup_tower_managed_defaults(mocker):
    return mocker.patch('awx.main.models.credential.CredentialType.setup_tower_managed_defaults')


@pytest.mark.django_db
def test_sync_credential_types_migrations_ran(mocker, mock_setup_tower_managed_defaults):
    mocker.patch('awx.main.tasks.system.is_database_synchronized', return_value=True)

    from awx.main.tasks.system import _sync_credential_types_to_db

    _sync_credential_types_to_db()

    mock_setup_tower_managed_defaults.assert_called_once()


@pytest.mark.django_db
def test_sync_credential_types_migrations_not_ran(mocker, mock_setup_tower_managed_defaults):
    mocker.patch('awx.main.tasks.system.is_database_synchronized', return_value=False)

    from awx.main.tasks.system import _sync_credential_types_to_db

    _sync_credential_types_to_db()

    mock_setup_tower_managed_defaults.assert_not_called()
