from dispatcherd.worker.task import TaskWorker

from django.db import connection


class AWXTaskWorker(TaskWorker):

    def on_start(self) -> None:
        """Ensure the worker has a DB connection before the first task arrives."""
        connection.ensure_connection()

    def pre_task(self, message) -> None:
        """Clean up unusable connections before running each task."""
        connection.close_if_unusable_or_obsolete()
