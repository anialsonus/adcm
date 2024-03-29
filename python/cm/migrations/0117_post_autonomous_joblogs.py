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

# Generated by Django 3.2.19 on 2024-03-04 12:18

# Expected to be applied right after 0116,
# split was made, because of PostgreSQL behavior when populating and altering table in one transaction.
# For some reason, atomic=False failed to work

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("cm", "0116_autonomous_joblogs"),
    ]

    operations = [
        migrations.AlterField(
            model_name="joblog",
            name="script",
            field=models.CharField(max_length=1000),
        ),
        migrations.AlterField(
            model_name="joblog",
            name="script_type",
            field=models.CharField(
                choices=[("ansible", "ansible"), ("python", "python"), ("internal", "internal")], max_length=1000
            ),
        ),
        migrations.AlterField(
            model_name="joblog",
            name="status",
            field=models.CharField(
                choices=[
                    ("created", "created"),
                    ("success", "success"),
                    ("failed", "failed"),
                    ("running", "running"),
                    ("locked", "locked"),
                    ("aborted", "aborted"),
                    ("broken", "broken"),
                ],
                default="created",
                max_length=1000,
            ),
        ),
    ]
