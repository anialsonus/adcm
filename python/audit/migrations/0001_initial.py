# Generated by Django 3.2.15 on 2022-09-28 05:03

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AuditObject',
            fields=[
                (
                    'id',
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name='ID'
                    ),
                ),
                ('object_id', models.PositiveIntegerField()),
                ('object_name', models.CharField(max_length=253)),
                (
                    'object_type',
                    models.CharField(
                        choices=[
                            ('cluster', 'cluster'),
                            ('service', 'service'),
                            ('component', 'component'),
                            ('host', 'host'),
                            ('provider', 'provider'),
                            ('bundle', 'bundle'),
                            ('adcm', 'adcm'),
                            ('user', 'user'),
                            ('group', 'group'),
                            ('role', 'role'),
                            ('policy', 'policy'),
                        ],
                        max_length=16,
                    ),
                ),
                ('is_deleted', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='AuditSession',
            fields=[
                (
                    'id',
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name='ID'
                    ),
                ),
                (
                    'login_result',
                    models.CharField(
                        choices=[
                            ('success', 'success'),
                            ('wrong password', 'wrong password'),
                            ('account disabled', 'account disabled'),
                            ('user not found', 'user not found'),
                        ],
                        max_length=64,
                    ),
                ),
                ('login_time', models.DateTimeField(auto_now_add=True)),
                ('login_details', models.JSONField(default=dict, null=True)),
                (
                    'user',
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                (
                    'id',
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name='ID'
                    ),
                ),
                ('operation_name', models.CharField(max_length=160)),
                (
                    'operation_type',
                    models.CharField(
                        choices=[('create', 'create'), ('update', 'update'), ('delete', 'delete')],
                        max_length=16,
                    ),
                ),
                (
                    'operation_result',
                    models.CharField(
                        choices=[('success', 'success'), ('fail', 'fail'), ('denied', 'denied')],
                        max_length=16,
                    ),
                ),
                ('operation_time', models.DateTimeField(auto_now_add=True)),
                ('object_changes', models.JSONField(default=dict)),
                (
                    'audit_object',
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to='audit.auditobject',
                    ),
                ),
                (
                    'user',
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
