from django.conf import settings

from ansible_base.lib.utils.db import get_pg_notify_params

from awx.main.dispatch import get_task_queuename
from awx.main.dispatch.pool import get_auto_max_workers


def get_dispatcherd_config(for_service: bool = False, mock_publish: bool = False) -> dict:
    """Return a configuration dictionary for dispatcherd."""
    if mock_publish:
        max_workers = 20
    else:
        max_workers = get_auto_max_workers()

    config = {
        "version": 2,
        "service": {
            "pool_kwargs": {"min_workers": settings.JOB_EVENT_WORKERS, "max_workers": max_workers},
            "main_kwargs": {"node_id": settings.CLUSTER_HOST_ID},
            "process_manager_cls": "ForkServerManager",
            "process_manager_kwargs": {"preload_modules": ['awx.main.dispatch.prefork']},
        },
        "brokers": {},
        "publish": {},
        "worker": {"worker_cls": "awx.main.dispatch.worker.dispatcherd.AWXTaskWorker"},
    }

    if mock_publish:
        config["brokers"]["dispatcherd.testing.brokers.noop"] = {}
        config["publish"]["default_broker"] = "dispatcherd.testing.brokers.noop"
    else:
        config["brokers"]["pg_notify"] = {
            "config": get_pg_notify_params(),
            "sync_connection_factory": "ansible_base.lib.utils.db.psycopg_connection_from_django",
            "default_publish_channel": settings.CLUSTER_HOST_ID,
        }
        config["publish"]["default_broker"] = "pg_notify"

    if for_service:
        config["producers"] = {
            "ScheduledProducer": {"task_schedule": settings.DISPATCHER_SCHEDULE},
            "OnStartProducer": {"task_list": {"awx.main.tasks.system.dispatch_startup": {}}},
            "ControlProducer": {},
        }
        if "pg_notify" in config["brokers"]:
            config["brokers"]["pg_notify"]["channels"] = ['tower_broadcast_all', 'tower_settings_change', get_task_queuename()]

    return config
