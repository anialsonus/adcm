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

# Generated by Django 2.2.1 on 2019-09-26 16:00

from django.db import migrations


def add_group(apps, proto):
    PrototypeConfig = apps.get_model("cm", "PrototypeConfig")
    if PrototypeConfig.objects.filter(prototype=proto, type="group"):
        return
    group = {}
    for pc in PrototypeConfig.objects.filter(prototype=proto).exclude(subname=""):
        group[pc.name] = True

    for name in group:
        pc = PrototypeConfig(prototype=proto, name=name, display_name=name, type="group", limits="{}")
        pc.save()


def fix_groups(apps, schema_editor):
    Prototype = apps.get_model("cm", "Prototype")
    for p in Prototype.objects.all():
        add_group(apps, p)


class Migration(migrations.Migration):
    dependencies = [
        ("cm", "0030_auto_20190820_1600"),
    ]

    operations = [
        migrations.RunPython(fix_groups),
    ]
