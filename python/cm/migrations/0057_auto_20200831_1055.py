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

# Generated by Django 3.1 on 2020-08-31 10:55

from django.db import migrations, models

import cm.models


def fix_default_json_fields_component(apps, schema_editor):
    Component = apps.get_model("cm", "Component")
    Component.objects.filter(constraint__exact="").update(constraint='[0, "+"]')
    Component.objects.filter(requires__exact="").update(requires="[]")
    Component.objects.filter(params__exact="").update(params="{}")


def fix_default_json_fields_action(apps, schema_editor):
    Action = apps.get_model("cm", "Action")
    Action.objects.filter(params__exact="").update(params="{}")
    Action.objects.filter(state_available__exact="").update(state_available="[]")
    Action.objects.filter(log_files__exact="").update(log_files="[]")
    Action.objects.filter(hostcomponentmap__exact="").update(hostcomponentmap="[]")


def fix_default_json_fields_subaction(apps, schema_editor):
    SubAction = apps.get_model("cm", "SubAction")
    SubAction.objects.filter(params__exact="").update(params="{}")


def fix_default_json_fields_upgrade(apps, schema_editor):
    Upgrade = apps.get_model("cm", "Upgrade")
    Upgrade.objects.filter(state_available__exact="").update(state_available="[]")


def fix_default_json_fields_adcm(apps, schema_editor):
    ADCM = apps.get_model("cm", "ADCM")
    ADCM.objects.filter(stack__exact="").update(stack="[]")


def fix_default_json_fields_cluster(apps, schema_editor):
    Cluster = apps.get_model("cm", "Cluster")
    Cluster.objects.filter(stack__exact="").update(stack="[]")
    Cluster.objects.filter(issue__exact="").update(issue="{}")


def fix_default_json_fields_hostprovider(apps, schema_editor):
    HostProvider = apps.get_model("cm", "HostProvider")
    HostProvider.objects.filter(stack__exact="").update(stack="[]")
    HostProvider.objects.filter(issue__exact="").update(issue="{}")


def fix_default_json_fields_host(apps, schema_editor):
    Host = apps.get_model("cm", "Host")
    Host.objects.filter(stack__exact="").update(stack="[]")
    Host.objects.filter(issue__exact="").update(issue="{}")


def fix_default_json_fields_clusterobject(apps, schema_editor):
    ClusterObject = apps.get_model("cm", "ClusterObject")
    ClusterObject.objects.filter(stack__exact="").update(stack="[]")
    ClusterObject.objects.filter(issue__exact="").update(issue="{}")


def fix_default_json_fields_userprofile(apps, schema_editor):
    UserProfile = apps.get_model("cm", "UserProfile")
    UserProfile.objects.filter(profile__exact="").update(profile='""')


def fix_default_json_fields_joblog(apps, schema_editor):
    JobLog = apps.get_model("cm", "JobLog")
    JobLog.objects.filter(selector__exact="").update(selector="{}")
    JobLog.objects.filter(log_files__exact="").update(log_files="[]")


def fix_default_json_fields_tasklog(apps, schema_editor):
    TaskLog = apps.get_model("cm", "TaskLog")
    TaskLog.objects.filter(selector__exact="").update(selector="{}")


class Migration(migrations.Migration):
    dependencies = [
        ("cm", "0056_auto_20200714_0741"),
    ]

    operations = [
        migrations.RunPython(fix_default_json_fields_component),
        migrations.RunPython(fix_default_json_fields_action),
        migrations.RunPython(fix_default_json_fields_subaction),
        migrations.RunPython(fix_default_json_fields_upgrade),
        migrations.RunPython(fix_default_json_fields_adcm),
        migrations.RunPython(fix_default_json_fields_cluster),
        migrations.RunPython(fix_default_json_fields_hostprovider),
        migrations.RunPython(fix_default_json_fields_host),
        migrations.RunPython(fix_default_json_fields_clusterobject),
        migrations.RunPython(fix_default_json_fields_userprofile),
        migrations.RunPython(fix_default_json_fields_joblog),
        migrations.RunPython(fix_default_json_fields_tasklog),
        migrations.AlterField(
            model_name="action",
            name="hostcomponentmap",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="action",
            name="log_files",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="action",
            name="params",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="action",
            name="state_available",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="action",
            name="ui_options",
            field=models.JSONField(default=None, null=True),
        ),
        migrations.AlterField(
            model_name="adcm",
            name="issue",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="adcm",
            name="stack",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="cluster",
            name="issue",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="cluster",
            name="stack",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="clusterobject",
            name="issue",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="clusterobject",
            name="stack",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="component",
            name="constraint",
            field=models.JSONField(default=[0, "+"]),
        ),
        migrations.AlterField(
            model_name="component",
            name="params",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="component",
            name="requires",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="host",
            name="issue",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="host",
            name="stack",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="hostprovider",
            name="issue",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="hostprovider",
            name="stack",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="joblog",
            name="log_files",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="joblog",
            name="selector",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="prototypeimport",
            name="default",
            field=models.JSONField(default=None, null=True),
        ),
        migrations.AlterField(
            model_name="stageaction",
            name="hostcomponentmap",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="stageaction",
            name="log_files",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="stageaction",
            name="params",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="stageaction",
            name="state_available",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="stageaction",
            name="ui_options",
            field=models.JSONField(default=None, null=True),
        ),
        migrations.AlterField(
            model_name="stagecomponent",
            name="constraint",
            field=models.JSONField(default=[0, "+"]),
        ),
        migrations.AlterField(
            model_name="stagecomponent",
            name="params",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="stagecomponent",
            name="requires",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="stageprototypeimport",
            name="default",
            field=models.JSONField(default=None, null=True),
        ),
        migrations.AlterField(
            model_name="stagesubaction",
            name="params",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="stageupgrade",
            name="from_edition",
            field=models.JSONField(default=cm.models.get_default_from_edition),
        ),
        migrations.AlterField(
            model_name="stageupgrade",
            name="state_available",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="subaction",
            name="params",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="tasklog",
            name="attr",
            field=models.JSONField(default=None, null=True),
        ),
        migrations.AlterField(
            model_name="tasklog",
            name="config",
            field=models.JSONField(default=None, null=True),
        ),
        migrations.AlterField(
            model_name="tasklog",
            name="hostcomponentmap",
            field=models.JSONField(default=None, null=True),
        ),
        migrations.AlterField(
            model_name="tasklog",
            name="hosts",
            field=models.JSONField(default=None, null=True),
        ),
        migrations.AlterField(
            model_name="tasklog",
            name="selector",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="upgrade",
            name="from_edition",
            field=models.JSONField(default=cm.models.get_default_from_edition),
        ),
        migrations.AlterField(
            model_name="upgrade",
            name="state_available",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="userprofile",
            name="profile",
            field=models.JSONField(default=str),
        ),
    ]
