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
# Generated by Django 3.2.6 on 2021-11-22 10:48
# Generated by Django 3.2.9 on 2022-01-18 10:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rbac', '0011_remove_user_group'),
    ]

    operations = [
        migrations.AddField(
            model_name='policy',
            name='description',
            field=models.TextField(blank=True),
        ),
    ]
