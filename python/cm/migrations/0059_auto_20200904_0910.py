# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Generated by Django 3.0.5 on 2020-09-04 09:10

import cm.models
from django.db import migrations


def fix_default_json_fields_action(apps, schema_editor):
    Action = apps.get_model('cm', 'Action')
    Action.objects.filter(ui_options__exact='').update(ui_options='{}')
    Action.objects.filter(ui_options__exact=None).update(ui_options='{}')


def fix_default_json_fields_tasklog(apps, schema_editor):
    TaskLog = apps.get_model('cm', 'TaskLog')
    TaskLog.objects.filter(attr__exact='').update(attr='{}')
    TaskLog.objects.filter(attr__exact=None).update(attr='{}')


def fix_default_json_fields_configlog(apps, schema_editor):
    ConfigLog = apps.get_model('cm', 'ConfigLog')
    ConfigLog.objects.filter(attr__exact='').update(attr='{}')
    ConfigLog.objects.filter(attr__exact=None).update(attr='{}')
    ConfigLog.objects.filter(config__exact='').update(config='{}')


def fix_default_json_fields_prototypeconfig(apps, schema_editor):
    PrototypeConfig = apps.get_model('cm', 'PrototypeConfig')
    PrototypeConfig.objects.filter(limits__exact='').update(limits='{}')
    PrototypeConfig.objects.filter(ui_options__exact='').update(ui_options='{}')


class Migration(migrations.Migration):

    dependencies = [
        ('cm', '0058_encrypt_passwords'),
    ]

    operations = [
        migrations.RunPython(fix_default_json_fields_action),
        migrations.RunPython(fix_default_json_fields_tasklog),
        migrations.RunPython(fix_default_json_fields_configlog),
        migrations.RunPython(fix_default_json_fields_prototypeconfig),
        migrations.AlterField(
            model_name='action',
            name='ui_options',
            field=cm.models.JSONField(default={}),
        ),
        migrations.AlterField(
            model_name='configlog',
            name='attr',
            field=cm.models.JSONField(default={}),
        ),
        migrations.AlterField(
            model_name='configlog',
            name='config',
            field=cm.models.JSONField(default={}),
        ),
        migrations.AlterField(
            model_name='prototypeconfig',
            name='limits',
            field=cm.models.JSONField(default={}),
        ),
        migrations.AlterField(
            model_name='prototypeconfig',
            name='ui_options',
            field=cm.models.JSONField(blank=True, default={}),
        ),
        migrations.AlterField(
            model_name='stageaction',
            name='ui_options',
            field=cm.models.JSONField(default={}),
        ),
        migrations.AlterField(
            model_name='stageprototypeconfig',
            name='limits',
            field=cm.models.JSONField(default={}),
        ),
        migrations.AlterField(
            model_name='stageprototypeconfig',
            name='ui_options',
            field=cm.models.JSONField(blank=True, default={}),
        ),
        migrations.AlterField(
            model_name='tasklog',
            name='attr',
            field=cm.models.JSONField(default={}),
        ),
    ]
