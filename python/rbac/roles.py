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

"""RBAC Role classes"""

from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from guardian.models import GroupObjectPermission, UserObjectPermission

from cm.errors import raise_adcm_ex
from cm.models import (
    Action,
    ADCMEntity,
    ClusterObject,
    ConfigLog,
    GroupConfig,
    Host,
    HostComponent,
    JobLog,
    LogStorage,
    ServiceComponent,
    TaskLog,
)
from rbac.models import (
    Group,
    Permission,
    Policy,
    PolicyPermission,
    Role,
    RoleTypes,
    User,
    get_objects_for_policy,
)


class AbstractRole:
    """Abstract class for custom Role handlers"""

    class Meta:
        abstract = True

    def __init__(self, **kwargs):
        self.params = kwargs

    def apply(self, policy: Policy, role: Role, user: User, group: Group, param_obj=None):
        """
        This method should apply Role to User and/or Group.
        Generaly this means that you should assign permissions from Role to User and/or Group
        and save links to these permissions in Policy model.
        If Role is parametrized_by_type than parametrized objects should be obtained from
        Policy.object field.
        Optional parameter param_obj can be used to specify the object in complex cases
        (see ParentRole below)
        """
        raise NotImplementedError("You must provide apply method")


class ModelRole(AbstractRole):
    """This Role apply Django model level permissions"""

    def apply(self, policy: Policy, role: Role, user: User, group: Group, param_obj=None):
        """Apply Role to User and/or Group"""
        for perm in role.get_permissions():
            if group is not None:
                group.permissions.add(perm)
                pp, _ = PolicyPermission.objects.get_or_create(group=group, permission=perm)
                policy.model_perm.add(pp)
            if user is not None:
                user.user_permissions.add(perm)
                pp, _ = PolicyPermission.objects.get_or_create(user=user, permission=perm)
                policy.model_perm.add(pp)


def assign_user_or_group_perm(user: User | None, group: Group | None, policy: Policy, perm: Permission, obj) -> None:
    with transaction.atomic():
        if user is not None:
            uop = UserObjectPermission.objects.assign_perm(perm, user, obj)
            policy.user_object_perm.add(uop)

        if group is not None:
            gop = GroupObjectPermission.objects.assign_perm(perm, group, obj)
            policy.group_object_perm.add(gop)


class ObjectRole(AbstractRole):
    """This Role apply django-guardian object level permissions"""

    def filter(self):
        if "model" not in self.params:
            return None
        try:
            model = apps.get_model(self.params["app_name"], self.params["model"])
        except LookupError as e:
            raise_adcm_ex("ROLE_FILTER_ERROR", str(e))
        return model.objects.filter(**self.params["filter"])

    def apply(self, policy: Policy, role: Role, user: User, group: Group, param_obj=None):
        """Apply Role to User and/or Group"""
        for obj in policy.get_objects(param_obj):
            for perm in role.get_permissions():
                assign_user_or_group_perm(user=user, group=group, policy=policy, perm=perm, obj=obj)


def get_host_objects(obj):
    object_type = obj.prototype.type
    host_list = []
    if object_type == "cluster":
        for host in Host.obj.filter(cluster=obj):
            host_list.append(host)
    elif object_type == "service":
        for hc in HostComponent.obj.filter(cluster=obj.cluster, service=obj):
            host_list.append(hc.host)
    elif object_type == "component":
        for hc in HostComponent.obj.filter(cluster=obj.cluster, service=obj.service, component=obj):
            host_list.append(hc.host)
    elif object_type == "provider":
        for host in Host.obj.filter(provider=obj):
            host_list.append(host)

    return host_list


class ActionRole(AbstractRole):
    """This Role apply permissions to run ADCM action"""

    def filter(self):
        if "model" not in self.params:
            return None
        try:
            model = apps.get_model(self.params["app_name"], self.params["model"])
        except LookupError as e:
            raise_adcm_ex("ROLE_FILTER_ERROR", str(e))
        return model.objects.filter(**self.params["filter"])

    def apply(self, policy: Policy, role: Role, user: User, group: Group = None, param_obj=None):
        """Apply Role to User and/or Group"""
        action = Action.obj.get(id=self.params["action_id"])
        assign_user_or_group_perm(
            user=user, group=group, policy=policy, perm=get_perm_for_model(model=Action), obj=action
        )
        for obj in policy.get_objects(param_obj):
            for perm in role.get_permissions():
                if action.host_action and perm.content_type == ContentType.objects.get_for_model(Host):
                    hosts = get_host_objects(obj)
                    for host in hosts:
                        assign_user_or_group_perm(user=user, group=group, policy=policy, perm=perm, obj=host)
                    continue
                assign_user_or_group_perm(user=user, group=group, policy=policy, perm=perm, obj=obj)


class TaskRole(AbstractRole):
    def apply(self, policy: Policy, role: Role, user: User, group: Group, param_obj: ADCMEntity = None) -> None:
        task = TaskLog.objects.filter(id=self.params["task_id"]).first()
        if not task:
            role.delete()
            return

        for obj in policy.get_objects(param_obj):
            if obj == task.task_object:
                apply_jobs(task=task, policy=policy, user=user, group=group)

        return


def get_perm_for_model(model, action: str = "view") -> Permission:
    content_type = ContentType.objects.get_for_model(model=model)
    codename = f"{action}_{model.__name__.lower()}"
    perm, _ = Permission.objects.get_or_create(content_type=content_type, codename=codename)
    return perm


def apply_jobs(task: TaskLog, policy: Policy, user: User, group: Group = None) -> None:
    assign_user_or_group_perm(user=user, group=group, policy=policy, perm=get_perm_for_model(model=TaskLog), obj=task)
    assign_user_or_group_perm(
        user=user, group=group, policy=policy, perm=get_perm_for_model(model=TaskLog, action="change"), obj=task
    )
    for job in JobLog.objects.filter(task=task):
        assign_user_or_group_perm(user=user, group=group, policy=policy, perm=get_perm_for_model(model=JobLog), obj=job)
        for log in LogStorage.objects.filter(job=job):
            assign_user_or_group_perm(
                user=user, group=group, policy=policy, perm=get_perm_for_model(model=LogStorage), obj=log
            )


def re_apply_policy_for_jobs(action_object, task):
    obj_type_map = get_objects_for_policy(action_object)
    object_model = action_object.__class__.__name__.lower()
    task_role, _ = Role.objects.get_or_create(
        name=f"View role for task {task.id}",
        display_name=f"View role for task {task.id}",
        description="View tasklog object with following joblog and logstorage",
        type=RoleTypes.hidden,
        module_name="rbac.roles",
        class_name="TaskRole",
        init_params={
            "task_id": task.id,
        },
        parametrized_by_type=[task.task_object.prototype.type],
    )

    for obj, content_type in obj_type_map.items():
        for policy in Policy.objects.filter(object__object_id=obj.id, object__content_type=content_type):
            for user in policy.user.all():
                try:
                    user_obj_perm = UserObjectPermission.objects.get(
                        user=user, permission__codename="view_action", object_pk=task.action.pk
                    )
                except UserObjectPermission.DoesNotExist:
                    continue

                if user_obj_perm in policy.user_object_perm.all() and user.has_perm(
                    perm=f"view_{object_model}", obj=action_object
                ):
                    policy.role.child.add(task_role)
                    apply_jobs(task=task, policy=policy, user=user, group=None)

            for group in policy.group.all():
                try:
                    group_obj_perm = GroupObjectPermission.objects.get(
                        group=group, permission__codename="view_action", object_pk=task.action.pk
                    )
                    model_view_gop = GroupObjectPermission.objects.get(
                        group=group,
                        permission__codename=f"view_{object_model}",
                        object_pk=action_object.pk,
                    )
                except GroupObjectPermission.DoesNotExist:
                    continue

                if group_obj_perm in policy.group_object_perm.all() and model_view_gop:
                    policy.role.child.add(task_role)
                    apply_jobs(task=task, policy=policy, user=None, group=group)


def apply_policy_for_new_config(config_object: ADCMEntity, config_log: ConfigLog) -> None:
    obj_type_map = get_objects_for_policy(obj=config_object)
    object_model = config_object.__class__.__name__.lower()

    for obj, content_type in obj_type_map.items():
        for policy in Policy.objects.filter(object__object_id=obj.id, object__content_type=content_type):
            for user in policy.user.all():
                try:
                    user_obj_perm = UserObjectPermission.objects.get(
                        user=user, permission__codename="view_objectconfig", object_pk=config_log.obj_ref_id
                    )
                except UserObjectPermission.DoesNotExist:
                    continue

                if user_obj_perm in policy.user_object_perm.all() and user.has_perm(
                    perm=f"view_{object_model}", obj=config_object
                ):
                    assign_user_or_group_perm(
                        user=user, group=None, policy=policy, perm=get_perm_for_model(model=ConfigLog), obj=config_log
                    )

            for group in policy.group.all():
                try:
                    group_obj_perm = GroupObjectPermission.objects.get(
                        group=group, permission__codename="view_objectconfig", object_pk=config_log.obj_ref_id
                    )
                    model_view_gop = GroupObjectPermission.objects.get(
                        group=group,
                        permission__codename=f"view_{object_model}",
                        object_pk=config_object.pk,
                    )
                except GroupObjectPermission.DoesNotExist:
                    continue

                if group_obj_perm in policy.group_object_perm.all() and model_view_gop:
                    assign_user_or_group_perm(
                        user=None, group=group, policy=policy, perm=get_perm_for_model(model=ConfigLog), obj=config_log
                    )


class ConfigRole(AbstractRole):
    """This Role apply permission to view and add config object"""

    def apply(self, policy: Policy, role: Role, user: User, group: Group, param_obj=None):
        for obj in policy.get_objects(param_obj=param_obj):
            if obj.config is None:
                continue

            object_type = ContentType.objects.get_for_model(obj)
            config_groups = GroupConfig.objects.filter(object_type=object_type, object_id=obj.id)

            for perm in role.get_permissions():
                if perm.content_type.model == "objectconfig":
                    assign_user_or_group_perm(user=user, group=group, policy=policy, perm=perm, obj=obj.config)
                    for cg in config_groups:
                        assign_user_or_group_perm(user=user, group=group, policy=policy, perm=perm, obj=cg.config)

                if perm.content_type.model == "configlog":
                    for config in obj.config.configlog_set.all():
                        assign_user_or_group_perm(user=user, group=group, policy=policy, perm=perm, obj=config)
                    for cg in config_groups:
                        for config in cg.config.configlog_set.all():
                            assign_user_or_group_perm(user=user, group=group, policy=policy, perm=perm, obj=config)

                if perm.content_type.model == "groupconfig":
                    for cg in config_groups:
                        assign_user_or_group_perm(user=user, group=group, policy=policy, perm=perm, obj=cg)


class ParentRole(AbstractRole):
    """This Role is used for complex Roles that can include other Roles"""

    @staticmethod
    def find_and_apply(obj: ADCMEntity, policy: Policy, role: Role, user: User, group: Group = None) -> None:
        """Find Role of appropriate type and apply it to specified object"""
        for child_role in role.child.filter(class_name__in=("ObjectRole", "TaskRole", "ConfigRole")):
            if obj.prototype.type in child_role.parametrized_by_type:
                child_role.apply(policy=policy, user=user, group=group, obj=obj)

        for child_role in role.child.filter(class_name="ActionRole"):
            action = Action.obj.get(id=child_role.init_params["action_id"])
            if obj.prototype == action.prototype:
                child_role.apply(policy=policy, user=user, group=group, obj=obj)

    def apply(
        self, policy: Policy, role: Role, user: User, group: Group = None, param_obj=None
    ):  # pylint: disable=too-many-branches, too-many-nested-blocks
        """Apply Role to User and/or Group"""
        for child_role in role.child.filter(class_name__in=("ModelRole", "ParentRole")):
            child_role.apply(policy=policy, user=user, group=group, obj=param_obj)

        parametrized_by = set()
        for child_role in role.child.all():
            parametrized_by.update(set(child_role.parametrized_by_type))

        for obj in policy.get_objects(param_obj=param_obj):
            view_cluster_perm = Permission.objects.get(codename="view_cluster")
            view_service_perm = Permission.objects.get(codename="view_clusterobject")

            self.find_and_apply(obj=obj, policy=policy, role=role, user=user, group=group)

            if obj.prototype.type == "cluster":
                if "service" in parametrized_by or "component" in parametrized_by:
                    for service in ClusterObject.obj.filter(cluster=obj):
                        self.find_and_apply(obj=service, policy=policy, role=role, user=user, group=group)
                        if "component" in parametrized_by:
                            for comp in ServiceComponent.obj.filter(service=service):
                                self.find_and_apply(obj=comp, policy=policy, role=role, user=user, group=group)
                if "host" in parametrized_by:
                    for host in Host.obj.filter(cluster=obj):
                        self.find_and_apply(obj=host, policy=policy, role=role, user=user, group=group)

            elif obj.prototype.type == "service":
                if "component" in parametrized_by:
                    for comp in ServiceComponent.obj.filter(service=obj):
                        self.find_and_apply(obj=comp, policy=policy, role=role, user=user, group=group)
                if "host" in parametrized_by:
                    for hc in HostComponent.obj.filter(cluster=obj.cluster, service=obj):
                        self.find_and_apply(obj=hc.host, policy=policy, role=role, user=user, group=group)
                assign_user_or_group_perm(
                    user=user, group=group, policy=policy, perm=view_cluster_perm, obj=obj.cluster
                )

            elif obj.prototype.type == "component":
                if "host" in parametrized_by:
                    for hc in HostComponent.obj.filter(cluster=obj.cluster, service=obj.service, component=obj):
                        self.find_and_apply(obj=hc.host, policy=policy, role=role, user=user, group=group)
                assign_user_or_group_perm(
                    user=user, group=group, policy=policy, perm=view_cluster_perm, obj=obj.cluster
                )
                assign_user_or_group_perm(
                    user=user, group=group, policy=policy, perm=view_service_perm, obj=obj.service
                )

            elif obj.prototype.type == "provider":
                if "host" in parametrized_by:
                    for host in Host.obj.filter(provider=obj):
                        self.find_and_apply(obj=host, policy=policy, role=role, user=user, group=group)
