# Generated by Django 3.1.2 on 2022-05-26 12:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cm', '0087_maintenance_mode'),
    ]

    operations = [
        migrations.AddField(
            model_name='tasklog',
            name='post_upgrade_hc_map',
            field=models.JSONField(default=None, null=True),
        ),
    ]
