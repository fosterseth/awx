import pytest
import copy
import json
import logging
import os
import tempfile
import shutil
from unittest import mock

from awx.main.tasks.jobs import RunJob
from awx.main.tasks.system import CleanupImagesAndFiles, execution_node_health_check, clear_setting_cache
from awx.main.models import Instance, Job

from awx.main.management.commands.run_dispatcher import Command


@pytest.mark.django_db
@pytest.mark.parametrize('node_type', ('control. hybrid'))
def test_no_worker_info_on_AWX_nodes(node_type):
    hostname = 'us-south-3-compute.invalid'
    Instance.objects.create(hostname=hostname, node_type=node_type)
    assert execution_node_health_check(hostname) is None


@pytest.fixture
def job_folder_factory(request):
    def _rf(job_id='1234'):
        pdd_path = tempfile.mkdtemp(prefix=f'awx_{job_id}_')

        def test_folder_cleanup():
            if os.path.exists(pdd_path):
                shutil.rmtree(pdd_path)

        request.addfinalizer(test_folder_cleanup)

        return pdd_path

    return _rf


@pytest.fixture
def mock_job_folder(job_folder_factory):
    return job_folder_factory()


@pytest.mark.django_db
def test_folder_cleanup_stale_file(mock_job_folder, mock_me):
    CleanupImagesAndFiles.run()
    assert os.path.exists(mock_job_folder)  # grace period should protect folder from deletion

    CleanupImagesAndFiles.run(grace_period=0)
    assert not os.path.exists(mock_job_folder)  # should be deleted


@pytest.mark.django_db
def test_folder_cleanup_running_job(mock_job_folder, me_inst):
    job = Job.objects.create(id=1234, controller_node=me_inst.hostname, status='running')
    CleanupImagesAndFiles.run(grace_period=0)
    assert os.path.exists(mock_job_folder)  # running job should prevent folder from getting deleted

    job.status = 'failed'
    job.save(update_fields=['status'])
    CleanupImagesAndFiles.run(grace_period=0)
    assert not os.path.exists(mock_job_folder)  # job is finished and no grace period, should delete


@pytest.mark.django_db
def test_folder_cleanup_multiple_running_jobs(job_folder_factory, me_inst):
    jobs = []
    dirs = []
    num_jobs = 3

    for i in range(num_jobs):
        job = Job.objects.create(controller_node=me_inst.hostname, status='running')
        dirs.append(job_folder_factory(job.id))
        jobs.append(job)

    CleanupImagesAndFiles.run(grace_period=0)

    assert [os.path.exists(d) for d in dirs] == [True for i in range(num_jobs)]


@pytest.mark.django_db
def test_does_not_run_reaped_job(mocker, mock_me):
    job = Job.objects.create(status='failed', job_explanation='This job has been reaped.')
    mock_run = mocker.patch('awx.main.tasks.jobs.ansible_runner.interface.run')
    try:
        RunJob().run(job.id)
    except Exception:
        pass
    job.refresh_from_db()
    assert job.status == 'failed'
    mock_run.assert_not_called()


@pytest.mark.django_db
def test_clear_setting_cache_log_level_branch(settings):
    settings.LOG_AGGREGATOR_LEVEL = 'DEBUG'
    settings.CLUSTER_HOST_ID = 'control-node'
    published_messages = []

    class DummyBroker:
        def publish_message(self, channel, message):
            published_messages.append((channel, message))

        def close(self):
            pass

    dummy_broker = DummyBroker()

    with mock.patch('dispatcherd.control.get_broker', return_value=dummy_broker) as mock_get_broker:
        clear_setting_cache(['LOG_AGGREGATOR_LEVEL'])

    mock_get_broker.assert_called_once()
    assert published_messages, 'control command was not sent through the broker'
    queue, payload = published_messages[-1]
    assert queue == 'control-node'
    body = json.loads(payload)
    assert body['control'] == 'set_log_level'
    assert body['control_data'] == {'level': 'DEBUG'}


@pytest.mark.django_db
def test_configure_dispatcher_logging_updates_level(settings):
    original_logging_settings = copy.deepcopy(settings.LOGGING)
    settings.LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'filters': {
            'dynamic_level_filter': {
                '()': 'logging.Filter',
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'filters': ['dynamic_level_filter'],
                'stream': 'ext://sys.stdout',
            }
        },
        'loggers': {
            'dispatcherd': {
                'handlers': ['console'],
                'level': 'INFO',
                'propagate': False,
            }
        },
    }
    settings.LOG_AGGREGATOR_LEVEL = 'WARNING'

    Command().configure_dispatcher_logging()

    assert logging.getLogger('dispatcherd').level == logging.WARNING
    settings.LOGGING = original_logging_settings
