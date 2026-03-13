import logging

from django.db import migrations


class RunSQL(migrations.operations.special.RunSQL):
    """
    Bit of a hack here. Django actually wants this decision made in the router
    and we can pass **hints.
    """

    def __init__(self, *args, **kwargs):
        if 'sqlite_sql' not in kwargs:
            raise ValueError("sqlite_sql parameter required")
        sqlite_sql = kwargs.pop('sqlite_sql')

        self.sqlite_sql = sqlite_sql
        self.sqlite_reverse_sql = kwargs.pop('sqlite_reverse_sql', None)
        super().__init__(*args, **kwargs)

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if not schema_editor.connection.vendor.startswith('postgres'):
            self.sql = self.sqlite_sql or migrations.RunSQL.noop
        super().database_forwards(app_label, schema_editor, from_state, to_state)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if not schema_editor.connection.vendor.startswith('postgres'):
            self.reverse_sql = self.sqlite_reverse_sql or migrations.RunSQL.noop
        super().database_backwards(app_label, schema_editor, from_state, to_state)


class RunPython(migrations.operations.special.RunPython):
    """
    Bit of a hack here. Django actually wants this decision made in the router
    and we can pass **hints.
    """

    def __init__(self, *args, **kwargs):
        if 'sqlite_code' not in kwargs:
            raise ValueError("sqlite_code parameter required")
        sqlite_code = kwargs.pop('sqlite_code')

        self.sqlite_code = sqlite_code
        self.sqlite_reverse_code = kwargs.pop('sqlite_reverse_code', None)
        super().__init__(*args, **kwargs)

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if not schema_editor.connection.vendor.startswith('postgres'):
            self.code = self.sqlite_code or migrations.RunPython.noop
        super().database_forwards(app_label, schema_editor, from_state, to_state)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if not schema_editor.connection.vendor.startswith('postgres'):
            self.reverse_code = self.sqlite_reverse_code or migrations.RunPython.noop
        super().database_backwards(app_label, schema_editor, from_state, to_state)


class AlterIndexTogether(migrations.operations.models.AlterIndexTogether):
    """
    SQLite-aware AlterIndexTogether that handles missing indexes gracefully.
    SQLite can drop indexes during table rewrites, causing Django to fail
    when trying to alter non-existent indexes.
    """

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if schema_editor.connection.vendor.startswith('sqlite'):
            # On SQLite, gracefully handle missing indexes
            try:
                super().database_forwards(app_label, schema_editor, from_state, to_state)
            except ValueError as e:
                error_msg = str(e)
                if "Found wrong number" in error_msg and ("constraints" in error_msg or "indexes" in error_msg):
                    # Index doesn't exist (was dropped during table rewrite), skip
                    logger = logging.getLogger(__name__)
                    logger.warning(f"Skipping AlterIndexTogether due to missing index on SQLite: {error_msg}")
                else:
                    raise
        else:
            super().database_forwards(app_label, schema_editor, from_state, to_state)


class RenameIndex(migrations.operations.models.RenameIndex):
    """
    SQLite-aware RenameIndex that handles missing indexes gracefully.
    SQLite can drop indexes during table rewrites, causing Django to fail
    when trying to rename non-existent indexes.
    """

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if schema_editor.connection.vendor.startswith('sqlite'):
            # On SQLite, gracefully handle missing indexes
            try:
                super().database_forwards(app_label, schema_editor, from_state, to_state)
            except ValueError as e:
                error_msg = str(e)
                if "Found wrong number" in error_msg and ("constraints" in error_msg or "indexes" in error_msg):
                    # Index doesn't exist (was dropped during table rewrite), skip
                    logger = logging.getLogger(__name__)
                    logger.warning(f"Skipping RenameIndex due to missing index on SQLite: {error_msg}")
                else:
                    raise
        else:
            super().database_forwards(app_label, schema_editor, from_state, to_state)


class _sqlitemigrations:
    RunPython = RunPython
    RunSQL = RunSQL
    AlterIndexTogether = AlterIndexTogether
    RenameIndex = RenameIndex


dbawaremigrations = _sqlitemigrations()
