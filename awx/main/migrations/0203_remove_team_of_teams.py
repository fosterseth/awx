import logging

from django.db import migrations

from awx.main.migrations._dab_rbac import consolidate_indirect_user_roles

logger = logging.getLogger('awx.main.migrations')


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0202_convert_controller_role_definitions'),
    ]

    operations = [
        migrations.RunPython(consolidate_indirect_user_roles, migrations.RunPython.noop),
    ]
