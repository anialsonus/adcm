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

# Generated by Django 3.2 on 2021-12-17 12:59

from django.db import migrations, models


role_category = {}


def pre_save_categories(apps, schema_editor):
    Role = apps.get_model('rbac', 'Role')
    ProductCategory = apps.get_model('cm', 'ProductCategory')

    for role in Role.objects.all():
        role_category[role.id] = []
        for value in role.category:
            category = ProductCategory.objects.filter(value=value).first()
            if category:
                role_category[role.id].append(category.id)


def update_categories(apps, schema_editor):
    displayed_for_all = {
        'Create host',
        'Remove hosts',
        'Map hosts',
        'Unmap hosts',
        'Upload bundle',
        'Upgrade bundle',
        'Remove bundle',
        'View configurations',
        'Edit configurations',
        'View imports',
        'Manage imports',
        'Add service',
        'Remove service',
    }

    Role = apps.get_model('rbac', 'Role')
    ProductCategory = apps.get_model('cm', 'ProductCategory')
    adcm_category = ProductCategory.objects.filter(value='ADCM').first()

    for role in Role.objects.all():
        for category_id in role_category[role.id]:
            category = ProductCategory.objects.filter(id=category_id).first()
            role.category.add(category)
        if adcm_category and role.type == 'business':
            role.category.add(adcm_category)
        if role.name in displayed_for_all:
            role.any_category = True
            role.save()


class Migration(migrations.Migration):

    dependencies = [
        ('cm', '0082_add_product_category'),
        ('rbac', '0008_add_indices_20211213_1900'),
    ]

    operations = [
        migrations.RunPython(pre_save_categories),
        migrations.RemoveField(
            model_name='role',
            name='category',
        ),
        migrations.AddField(
            model_name='role',
            name='category',
            field=models.ManyToManyField(to='cm.ProductCategory'),
        ),
        migrations.AddField(
            model_name='role',
            name='any_category',
            field=models.BooleanField(default=False),
        ),
        migrations.RunPython(update_categories),
    ]
