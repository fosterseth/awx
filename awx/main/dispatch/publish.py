import inspect
import json
import logging
import time
from uuid import uuid4

from dispatcherd.processors.blocker import Blocker
from dispatcherd.publish import submit_task
from dispatcherd.utils import resolve_callable
from django.conf import settings
from django_guid import get_guid

from . import pg_bus_conn

logger = logging.getLogger('awx.main.dispatch')


def serialize_task(f):
    return '.'.join([f.__module__, f.__name__])


class task:
    """
    Used to decorate a function or class so that it can be run asynchronously
    via the task dispatcher.  Tasks can be simple functions:

    @task()
    def add(a, b):
        return a + b

    ...or classes that define a `run` method:

    @task()
    class Adder:
        def run(self, a, b):
            return a + b

    # Tasks can be run synchronously...
    assert add(1, 1) == 2
    assert Adder().run(1, 1) == 2

    # ...or published to a queue:
    add.apply_async([1, 1])
    Adder.apply_async([1, 1])

    # Tasks can also define a specific target queue or use the special fan-out queue tower_broadcast:

    @task(queue='slow-tasks')
    def snooze():
        time.sleep(10)

    @task(queue='tower_broadcast')
    def announce():
        print("Run this everywhere!")

    # The special parameter bind_kwargs tells the main dispatcher process to add certain kwargs

    @task(bind_kwargs=['dispatch_time'])
    def print_time(dispatch_time=None):
        print(f"Time I was dispatched: {dispatch_time}")
    """

    def __init__(self, queue=None, bind_kwargs=None, timeout=None, on_duplicate=None):
        self.queue = queue
        self.bind_kwargs = bind_kwargs
        self.timeout = timeout
        self.on_duplicate = on_duplicate

    def __call__(self, fn=None):
        queue = self.queue
        bind_kwargs = self.bind_kwargs
        timeout = self.timeout
        on_duplicate = self.on_duplicate

        class PublisherMixin(object):
            queue = None

            @classmethod
            def delay(cls, *args, **kwargs):
                return cls.apply_async(args, kwargs)

            @classmethod
            def get_async_body(cls, args=None, kwargs=None, uuid=None, **kw):
                """
                Get the python dict to become JSON data in the pg_notify message
                This same message gets passed over the dispatcher IPC queue to workers
                If a task is submitted to a multiprocessing pool, skipping pg_notify, this might be used directly
                """
                task_id = uuid or str(uuid4())
                args = args or []
                kwargs = kwargs or {}
                obj = {'uuid': task_id, 'args': args, 'kwargs': kwargs, 'task': cls.name, 'time_pub': time.time()}
                guid = get_guid()
                if guid:
                    obj['guid'] = guid
                if bind_kwargs:
                    obj['bind_kwargs'] = bind_kwargs
                obj.update(**kw)
                return obj

            @classmethod
            def apply_async(cls, args=None, kwargs=None, queue=None, uuid=None, **kw):
                try:
                    from flags.state import flag_enabled

                    if flag_enabled('FEATURE_DISPATCHERD_ENABLED'):
                        actual_task = resolve_callable(cls.name)
                        processor_options = ()
                        if on_duplicate is not None:
                            processor_options = (Blocker.Params(on_duplicate=on_duplicate),)
                        return submit_task(
                            actual_task,
                            args=args,
                            kwargs=kwargs,
                            queue=queue,
                            uuid=uuid,
                            timeout=timeout,
                            processor_options=processor_options,
                            **kw,
                        )
                except Exception:
                    logger.exception(f"[DISPATCHER] Failed to check for alternative dispatcherd implementation for {cls.name}")

                queue_name = queue or getattr(cls.queue, 'im_func', cls.queue)
                if not queue_name:
                    msg = f'{cls.name}: Queue value required and may not be None'
                    logger.error(msg)
                    raise ValueError(msg)
                obj = cls.get_async_body(args=args, kwargs=kwargs, uuid=uuid, **kw)
                if callable(queue_name):
                    queue_name = queue_name()
                if not settings.DISPATCHER_MOCK_PUBLISH:
                    with pg_bus_conn() as conn:
                        conn.notify(queue_name, json.dumps(obj))
                return (obj, queue_name)

        bases = []
        ns = {'name': serialize_task(fn), 'queue': queue}
        if inspect.isclass(fn):
            bases = list(fn.__bases__)
            ns.update(fn.__dict__)
        cls = type(fn.__name__, tuple(bases + [PublisherMixin]), ns)
        if inspect.isclass(fn):
            return cls

        setattr(fn, 'name', cls.name)
        setattr(fn, 'apply_async', cls.apply_async)
        setattr(fn, 'delay', cls.delay)
        setattr(fn, 'get_async_body', cls.get_async_body)
        return fn
