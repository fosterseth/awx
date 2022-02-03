# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-12-14 15:13
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0017_v330_move_deprecated_stdout'),
    ]

    operations = [
        migrations.CreateModel(
            name='InventoryUpdateEvent',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(default=None, editable=False)),
                ('modified', models.DateTimeField(default=None, editable=False)),
                ('event_data', models.JSONField(default=dict)),
                ('uuid', models.CharField(default='', editable=False, max_length=1024)),
                ('counter', models.PositiveIntegerField(default=0, editable=False)),
                ('stdout', models.TextField(default='', editable=False)),
                ('verbosity', models.PositiveIntegerField(default=0, editable=False)),
                ('start_line', models.PositiveIntegerField(default=0, editable=False)),
                ('end_line', models.PositiveIntegerField(default=0, editable=False)),
                (
                    'inventory_update',
                    models.ForeignKey(
                        editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='inventory_update_events', to='main.InventoryUpdate'
                    ),
                ),
            ],
            options={
                'ordering': ('-pk',),
            },
        ),
        migrations.CreateModel(
            name='ProjectUpdateEvent',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(default=None, editable=False)),
                ('modified', models.DateTimeField(default=None, editable=False)),
                (
                    'event',
                    models.CharField(
                        choices=[
                            ('runner_on_failed', 'Host Failed'),
                            ('runner_on_ok', 'Host OK'),
                            ('runner_on_error', 'Host Failure'),
                            ('runner_on_skipped', 'Host Skipped'),
                            ('runner_on_unreachable', 'Host Unreachable'),
                            ('runner_on_no_hosts', 'No Hosts Remaining'),
                            ('runner_on_async_poll', 'Host Polling'),
                            ('runner_on_async_ok', 'Host Async OK'),
                            ('runner_on_async_failed', 'Host Async Failure'),
                            ('runner_item_on_ok', 'Item OK'),
                            ('runner_item_on_failed', 'Item Failed'),
                            ('runner_item_on_skipped', 'Item Skipped'),
                            ('runner_retry', 'Host Retry'),
                            ('runner_on_file_diff', 'File Difference'),
                            ('playbook_on_start', 'Playbook Started'),
                            ('playbook_on_notify', 'Running Handlers'),
                            ('playbook_on_include', 'Including File'),
                            ('playbook_on_no_hosts_matched', 'No Hosts Matched'),
                            ('playbook_on_no_hosts_remaining', 'No Hosts Remaining'),
                            ('playbook_on_task_start', 'Task Started'),
                            ('playbook_on_vars_prompt', 'Variables Prompted'),
                            ('playbook_on_setup', 'Gathering Facts'),
                            ('playbook_on_import_for_host', 'internal: on Import for Host'),
                            ('playbook_on_not_import_for_host', 'internal: on Not Import for Host'),
                            ('playbook_on_play_start', 'Play Started'),
                            ('playbook_on_stats', 'Playbook Complete'),
                            ('debug', 'Debug'),
                            ('verbose', 'Verbose'),
                            ('deprecated', 'Deprecated'),
                            ('warning', 'Warning'),
                            ('system_warning', 'System Warning'),
                            ('error', 'Error'),
                        ],
                        max_length=100,
                    ),
                ),
                ('event_data', models.JSONField(default=dict)),
                ('failed', models.BooleanField(default=False, editable=False)),
                ('changed', models.BooleanField(default=False, editable=False)),
                ('uuid', models.CharField(default='', editable=False, max_length=1024)),
                ('playbook', models.CharField(default='', editable=False, max_length=1024)),
                ('play', models.CharField(default='', editable=False, max_length=1024)),
                ('role', models.CharField(default='', editable=False, max_length=1024)),
                ('task', models.CharField(default='', editable=False, max_length=1024)),
                ('counter', models.PositiveIntegerField(default=0, editable=False)),
                ('stdout', models.TextField(default='', editable=False)),
                ('verbosity', models.PositiveIntegerField(default=0, editable=False)),
                ('start_line', models.PositiveIntegerField(default=0, editable=False)),
                ('end_line', models.PositiveIntegerField(default=0, editable=False)),
                (
                    'project_update',
                    models.ForeignKey(
                        editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='project_update_events', to='main.ProjectUpdate'
                    ),
                ),
            ],
            options={
                'ordering': ('pk',),
            },
        ),
        migrations.CreateModel(
            name='SystemJobEvent',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(default=None, editable=False)),
                ('modified', models.DateTimeField(default=None, editable=False)),
                ('event_data', models.JSONField(default=dict)),
                ('uuid', models.CharField(default='', editable=False, max_length=1024)),
                ('counter', models.PositiveIntegerField(default=0, editable=False)),
                ('stdout', models.TextField(default='', editable=False)),
                ('verbosity', models.PositiveIntegerField(default=0, editable=False)),
                ('start_line', models.PositiveIntegerField(default=0, editable=False)),
                ('end_line', models.PositiveIntegerField(default=0, editable=False)),
                (
                    'system_job',
                    models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='system_job_events', to='main.SystemJob'),
                ),
            ],
            options={
                'ordering': ('-pk',),
            },
        ),
        migrations.AlterIndexTogether(
            name='inventoryupdateevent',
            index_together=set([('inventory_update', 'start_line'), ('inventory_update', 'uuid'), ('inventory_update', 'end_line')]),
        ),
        migrations.AlterIndexTogether(
            name='projectupdateevent',
            index_together=set([('project_update', 'event'), ('project_update', 'end_line'), ('project_update', 'start_line'), ('project_update', 'uuid')]),
        ),
        migrations.AlterIndexTogether(
            name='systemjobevent',
            index_together=set([('system_job', 'end_line'), ('system_job', 'uuid'), ('system_job', 'start_line')]),
        ),
        migrations.RemoveField(
            model_name='unifiedjob',
            name='result_stdout_file',
        ),
    ]
