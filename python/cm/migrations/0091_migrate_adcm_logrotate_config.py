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

# Generated by Django 3.2.13 on 2022-06-02 13:35


from django.db import migrations


def migrate_logrotate_config(apps, schema_editor):
    ADCM = apps.get_model("cm", "ADCM")
    ConfigLog = apps.get_model("cm", "ConfigLog")

    adcm_object = ADCM.objects.first()
    if adcm_object is None:
        # run on a clean database, no migration required
        return

    adcm_configlog = ConfigLog.objects.get(obj_ref=adcm_object.config, id=adcm_object.config.current)

    # pylint: disable=simplifiable-if-statement
    if adcm_configlog.config.get("logrotate", {}).get("nginx_server", False):
        active_value = True
    else:
        active_value = False

    adcm_configlog.attr = {"logrotate": {"active": active_value}}
    adcm_configlog.save()


class Migration(migrations.Migration):
    dependencies = [
        ("cm", "0090_rm_background_tasks_app"),
    ]

    operations = [
        migrations.RunPython(migrate_logrotate_config),
    ]
