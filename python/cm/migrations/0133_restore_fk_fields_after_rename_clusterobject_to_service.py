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

# Generated by Django 3.2.23 on 2024-09-18 10:22

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("cm", "0132_rename_clusterobject_to_service"),
    ]

    operations = [
        migrations.AlterField(
            model_name="clusterbind",
            name="service",
            field=models.ForeignKey(
                default=None, null=True, on_delete=django.db.models.deletion.CASCADE, to="cm.service"
            ),
        ),
        migrations.AlterField(
            model_name="clusterbind",
            name="source_service",
            field=models.ForeignKey(
                default=None,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="source_service",
                to="cm.service",
            ),
        ),
        migrations.AlterField(
            model_name="hostcomponent",
            name="service",
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="cm.service"),
        ),
        migrations.AlterField(
            model_name="servicecomponent",
            name="service",
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="cm.service"),
        ),
        migrations.AlterField(
            model_name="service",
            name="cluster",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, related_name="services", to="cm.cluster"
            ),
        ),
    ]
