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

# Generated by Django 3.2.23 on 2024-06-06 05:56

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("cm", "0125_simplify_defaults"),
    ]

    operations = [
        migrations.AddField(
            model_name="action",
            name="allow_for_action_host_group",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="stageaction",
            name="allow_for_action_host_group",
            field=models.BooleanField(default=False),
        ),
        migrations.CreateModel(
            name="ActionHostGroup",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("object_id", models.PositiveIntegerField()),
                ("name", models.CharField(max_length=150)),
                ("description", models.CharField(max_length=255)),
                ("hosts", models.ManyToManyField(to="cm.Host")),
                (
                    "object_type",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="contenttypes.contenttype"),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
    ]
