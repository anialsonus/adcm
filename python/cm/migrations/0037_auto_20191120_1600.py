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

# Generated by Django 2.2.1 on 2019-11-20 16:00
import json

from django.db import migrations

from cm.logger import logger


def fix_task(apps, schema_editor):
    TaskLog = apps.get_model('cm', 'TaskLog')
    Action = apps.get_model('cm', 'Action')
    for task in TaskLog.objects.all():
        try:
            action = Action.objects.get(id=task.action_id)
        except Action.DoesNotExist:
            continue
        selector = json.loads(task.selector)
        if action.prototype.type == 'service':
            if 'service' not in selector:
                selector['service'] = task.object_id
                logger.debug('update task #%s new selector: %s', task.id, selector)
                task.selector = json.dumps(selector)
                task.save()


def fix_job(apps, schema_editor):
    JobLog = apps.get_model('cm', 'JobLog')
    TaskLog = apps.get_model('cm', 'TaskLog')
    Action = apps.get_model('cm', 'Action')
    for job in JobLog.objects.all():
        try:
            action = Action.objects.get(id=job.action_id)
        except Action.DoesNotExist:
            continue
        task = TaskLog.objects.get(id=job.task_id)
        selector = json.loads(job.selector)
        if action.prototype.type == 'service':
            if 'service' not in selector:
                selector['service'] = task.object_id
                logger.debug('update job #%s new selector: %s', job.id, selector)
                job.selector = json.dumps(selector)
                job.save()


class Migration(migrations.Migration):
    dependencies = [
        ('cm', '0036_auto_20191111_1109'),
    ]

    operations = [
        migrations.RunPython(fix_task),
        migrations.RunPython(fix_job),
    ]
