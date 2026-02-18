import django

from dispatcherd.brokers import pg_notify  # noqa: F401

from channels_redis import core  # noqa: F401

from awx import prepare_env
from dispatcherd.utils import resolve_callable

prepare_env()

django.setup()

from django.conf import settings  # noqa: E402
from django.core.cache import cache as django_cache  # noqa: E402
from django.db import connection  # noqa: E402

# Preload all periodic tasks so their imports will be in shared memory.
for name, options in settings.CELERYBEAT_SCHEDULE.items():
    resolve_callable(options['task'])

# Preload in-line import from tasks
from awx.main.scheduler.kubernetes import PodManager  # noqa: E402,F401

connection.close()
django_cache.close()
