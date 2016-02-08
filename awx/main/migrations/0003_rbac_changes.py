# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings
import taggit.managers
import awx.main.fields


class Migration(migrations.Migration):

    dependencies = [
        ('taggit', '0002_auto_20150616_2121'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('main', '0002_v300_changes'),
    ]

    operations = [
        migrations.CreateModel(
            name='Resource',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('created', models.DateTimeField(default=None, editable=False)),
                ('modified', models.DateTimeField(default=None, editable=False)),
                ('description', models.TextField(default=b'', blank=True)),
                ('active', models.BooleanField(default=True, editable=False)),
                ('name', models.CharField(max_length=512)),
                ('created_by', models.ForeignKey(related_name="{u'class': 'resource', u'app_label': 'main'}(class)s_created+", on_delete=django.db.models.deletion.SET_NULL, default=None, editable=False, to=settings.AUTH_USER_MODEL, null=True)),
                ('modified_by', models.ForeignKey(related_name="{u'class': 'resource', u'app_label': 'main'}(class)s_modified+", on_delete=django.db.models.deletion.SET_NULL, default=None, editable=False, to=settings.AUTH_USER_MODEL, null=True)),
                ('parent', models.ForeignKey(related_name='children', default=None, to='main.Resource', null=True)),
                ('tags', taggit.managers.TaggableManager(to='taggit.Tag', through='taggit.TaggedItem', blank=True, help_text='A comma-separated list of tags.', verbose_name='Tags')),
            ],
            options={
                'db_table': 'main_rbac_resources',
                'verbose_name_plural': 'resources',
            },
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('created', models.DateTimeField(default=None, editable=False)),
                ('modified', models.DateTimeField(default=None, editable=False)),
                ('description', models.TextField(default=b'', blank=True)),
                ('active', models.BooleanField(default=True, editable=False)),
                ('name', models.CharField(max_length=512)),
                ('singleton_name', models.TextField(default=None, unique=True, null=True, db_index=True)),
                ('created_by', models.ForeignKey(related_name="{u'class': 'role', u'app_label': 'main'}(class)s_created+", on_delete=django.db.models.deletion.SET_NULL, default=None, editable=False, to=settings.AUTH_USER_MODEL, null=True)),
                ('members', models.ManyToManyField(related_name='roles', to=settings.AUTH_USER_MODEL)),
                ('modified_by', models.ForeignKey(related_name="{u'class': 'role', u'app_label': 'main'}(class)s_modified+", on_delete=django.db.models.deletion.SET_NULL, default=None, editable=False, to=settings.AUTH_USER_MODEL, null=True)),
                ('parents', models.ManyToManyField(related_name='children', to='main.Role')),
                ('tags', taggit.managers.TaggableManager(to='taggit.Tag', through='taggit.TaggedItem', blank=True, help_text='A comma-separated list of tags.', verbose_name='Tags')),
            ],
            options={
                'db_table': 'main_rbac_roles',
                'verbose_name_plural': 'roles',
            },
        ),
        migrations.CreateModel(
            name='RoleHierarchy',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('created', models.DateTimeField(default=None, editable=False)),
                ('modified', models.DateTimeField(default=None, editable=False)),
                ('ancestor', models.ForeignKey(related_name='+', to='main.Role')),
                ('role', models.ForeignKey(related_name='+', to='main.Role')),
            ],
            options={
                'db_table': 'main_rbac_role_hierarchy',
                'verbose_name_plural': 'role_ancestors',
            },
        ),
        migrations.CreateModel(
            name='RolePermission',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('created', models.DateTimeField(default=None, editable=False)),
                ('modified', models.DateTimeField(default=None, editable=False)),
                ('create', models.IntegerField(default=0)),
                ('read', models.IntegerField(default=0)),
                ('write', models.IntegerField(default=0)),
                ('update', models.IntegerField(default=0)),
                ('delete', models.IntegerField(default=0)),
                ('execute', models.IntegerField(default=0)),
                ('scm_update', models.IntegerField(default=0)),
                ('use', models.IntegerField(default=0)),
                ('resource', models.ForeignKey(related_name='permissions', to='main.Resource')),
                ('role', models.ForeignKey(related_name='permissions', to='main.Role')),
            ],
            options={
                'db_table': 'main_rbac_permissions',
                'verbose_name_plural': 'permissions',
            },
        ),
        migrations.AddField(
            model_name='project',
            name='organization',
            field=models.ForeignKey(related_name='project_list', on_delete=django.db.models.deletion.SET_NULL, to='main.Organization', null=True),
        ),
        migrations.AddField(
            model_name='credential',
            name='owner_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='credential',
            name='resource',
            field=awx.main.fields.ImplicitResourceField(related_name='+', to='main.Resource', null=b'True'),
        ),
        migrations.AddField(
            model_name='credential',
            name='usage_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='group',
            name='admin_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='group',
            name='auditor_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='group',
            name='executor_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='group',
            name='resource',
            field=awx.main.fields.ImplicitResourceField(related_name='+', to='main.Resource', null=b'True'),
        ),
        migrations.AddField(
            model_name='group',
            name='updater_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='host',
            name='resource',
            field=awx.main.fields.ImplicitResourceField(related_name='+', to='main.Resource', null=b'True'),
        ),
        migrations.AddField(
            model_name='inventory',
            name='admin_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='inventory',
            name='auditor_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='inventory',
            name='executor_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='inventory',
            name='resource',
            field=awx.main.fields.ImplicitResourceField(related_name='+', to='main.Resource', null=b'True'),
        ),
        migrations.AddField(
            model_name='inventory',
            name='updater_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='inventorysource',
            name='resource',
            field=awx.main.fields.ImplicitResourceField(related_name='+', to='main.Resource', null=b'True'),
        ),
        migrations.AddField(
            model_name='jobtemplate',
            name='admin_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='jobtemplate',
            name='auditor_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='jobtemplate',
            name='executor_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='jobtemplate',
            name='resource',
            field=awx.main.fields.ImplicitResourceField(related_name='+', to='main.Resource', null=b'True'),
        ),
        migrations.AddField(
            model_name='organization',
            name='admin_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='organization',
            name='auditor_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='organization',
            name='resource',
            field=awx.main.fields.ImplicitResourceField(related_name='+', to='main.Resource', null=b'True'),
        ),
        migrations.AddField(
            model_name='project',
            name='admin_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='project',
            name='auditor_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='project',
            name='member_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='project',
            name='resource',
            field=awx.main.fields.ImplicitResourceField(related_name='+', to='main.Resource', null=b'True'),
        ),
        migrations.AddField(
            model_name='project',
            name='scm_update_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='team',
            name='admin_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='team',
            name='auditor_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='team',
            name='member_role',
            field=awx.main.fields.ImplicitRoleField(related_name='+', to='main.Role', null=b'True'),
        ),
        migrations.AddField(
            model_name='team',
            name='resource',
            field=awx.main.fields.ImplicitResourceField(related_name='+', to='main.Resource', null=b'True'),
        ),
    ]
