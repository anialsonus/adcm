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
# pylint: disable=too-many-lines

from typing import Optional, Tuple

from django.contrib.contenttypes.models import ContentType
from django.db.models import Model
from django.views import View
from rest_framework.response import Response

from audit.models import (
    AUDIT_OBJECT_TYPE_TO_MODEL_MAP,
    PATH_STR_TO_OBJ_CLASS_MAP,
    AuditLogOperationType,
    AuditObject,
    AuditObjectType,
    AuditOperation,
)
from cm.models import (
    ADCM,
    Action,
    Bundle,
    Cluster,
    ClusterBind,
    ClusterObject,
    GroupConfig,
    Host,
    HostProvider,
    ObjectConfig,
    ServiceComponent,
    TaskLog,
    Upgrade,
)
from rbac.models import Group, Policy, Role, User


def _get_audit_object_from_resp(response: Response, obj_type: str) -> Optional[AuditObject]:
    if response and response.data and response.data.get("id") and response.data.get("name"):
        audit_object = get_or_create_audit_obj(
            object_id=response.data["id"],
            object_name=response.data["name"],
            object_type=obj_type,
        )
    else:
        audit_object = None

    return audit_object


def _task_case(task_pk: str, action: str) -> Tuple[AuditOperation, AuditObject]:
    if action == "cancel":
        action = f"{action}l"

    obj = TaskLog.objects.get(pk=task_pk)
    obj_type = obj.object_type.name

    if obj_type == "adcm":
        obj_type = obj_type.upper()
    else:
        obj_type = obj_type.capitalize()

    if obj.action:
        action_name = obj.action.display_name
    else:
        action_name = "task"

    audit_operation = AuditOperation(
        name=f"{obj_type} {action_name} {action}ed",
        operation_type=AuditLogOperationType.Update,
    )
    audit_object = get_or_create_audit_obj(
        object_id=task_pk,
        object_name=obj.task_object.name,
        object_type=obj.object_type.name,
    )

    return audit_operation, audit_object


def _get_service_name(service: ClusterObject) -> str:
    if service.display_name:
        return service.display_name

    if service.prototype.name:
        return service.prototype.name

    return str(service)


def _get_obj_type(obj_type: str) -> str:
    if obj_type == "cluster object":
        return "service"
    elif obj_type == "service component":
        return "component"

    return obj_type


def get_or_create_audit_obj(object_id: str, object_name: str, object_type: str) -> AuditObject:
    audit_object = AuditObject.objects.filter(
        object_id=object_id,
        object_type=object_type,
    ).first()

    if not audit_object:
        audit_object = AuditObject.objects.create(
            object_id=object_id,
            object_name=object_name,
            object_type=object_type,
        )

    return audit_object


# pylint: disable-next=too-many-statements,too-many-branches,too-many-locals
def get_audit_operation_and_object(
    view: View, response: Response, deleted_obj: Model
) -> Tuple[Optional[AuditOperation], Optional[AuditObject], Optional[str]]:
    operation_name = None
    path = view.request.path.replace("/api/v1/", "")[:-1].split("/")

    match path:
        case ["stack", "upload"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Bundle.capitalize()} uploaded",
                operation_type=AuditLogOperationType.Create,
            )
            audit_object = None

        case ["stack", "load"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Bundle.capitalize()} loaded",
                operation_type=AuditLogOperationType.Create,
            )
            audit_object = _get_audit_object_from_resp(
                response=response,
                obj_type=AuditObjectType.Bundle,
            )

        case ["stack", "bundle", bundle_pk]:
            deleted_obj: Bundle
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Bundle.capitalize()} {AuditLogOperationType.Delete}d",
                operation_type=AuditLogOperationType.Delete,
            )
            audit_object = get_or_create_audit_obj(
                object_id=bundle_pk,
                object_name=deleted_obj.name,
                object_type=AuditObjectType.Bundle,
            )

        case ["stack", "bundle", bundle_pk, "update"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Bundle.capitalize()} {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = Bundle.objects.get(pk=bundle_pk)
            audit_object = get_or_create_audit_obj(
                object_id=bundle_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Bundle,
            )

        case ["stack", "bundle", bundle_pk, "license", "accept"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Bundle.capitalize()} license accepted",
                operation_type=AuditLogOperationType.Update,
            )
            obj = Bundle.objects.get(pk=bundle_pk)
            audit_object = get_or_create_audit_obj(
                object_id=bundle_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Bundle,
            )

        case ["cluster"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Cluster.capitalize()} " f"{AuditLogOperationType.Create}d",
                operation_type=AuditLogOperationType.Create,
            )
            audit_object = _get_audit_object_from_resp(
                response=response,
                obj_type=AuditObjectType.Cluster,
            )

        case ["cluster", cluster_pk]:
            if view.request.method == "DELETE":
                deleted_obj: Cluster
                operation_type = AuditLogOperationType.Delete
                obj = deleted_obj
            else:
                operation_type = AuditLogOperationType.Update
                obj = Cluster.objects.filter(pk=cluster_pk).first()

            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Cluster.capitalize()} {operation_type}d",
                operation_type=operation_type,
            )
            if obj:
                audit_object = get_or_create_audit_obj(
                    object_id=cluster_pk,
                    object_name=obj.name,
                    object_type=AuditObjectType.Cluster,
                )
            else:
                audit_object = None

        case ["cluster", cluster_pk, "host"]:
            audit_operation = AuditOperation(
                name="{host_fqdn} added",
                operation_type=AuditLogOperationType.Update,
            )

            host_fqdn = None
            if response and response.data:
                host_fqdn = response.data["fqdn"]

            if "host_id" in view.request.data:
                host = Host.objects.filter(pk=view.request.data["host_id"]).first()
                if host:
                    host_fqdn = host.fqdn

            if host_fqdn:
                audit_operation.name = audit_operation.name.format(host_fqdn=host_fqdn)

            obj = Cluster.objects.get(pk=cluster_pk)
            audit_object = get_or_create_audit_obj(
                object_id=cluster_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Cluster,
            )

        case ["cluster", cluster_pk, "hostcomponent"]:
            audit_operation = AuditOperation(
                name="Host-Component map updated",
                operation_type=AuditLogOperationType.Update,
            )
            obj = Cluster.objects.get(pk=cluster_pk)
            audit_object = get_or_create_audit_obj(
                object_id=cluster_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Cluster,
            )

        case ["cluster", cluster_pk, "import"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Cluster.capitalize()} "
                f"import {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = Cluster.objects.get(pk=cluster_pk)
            audit_object = get_or_create_audit_obj(
                object_id=cluster_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Cluster,
            )

        case ["cluster", cluster_pk, "service"]:
            audit_operation = AuditOperation(
                name="{service_display_name} service added",
                operation_type=AuditLogOperationType.Update,
            )

            service_display_name = None
            if response and response.data and response.data.get("display_name"):
                service_display_name = response.data["display_name"]

            if "service_id" in view.request.data:
                service = ClusterObject.objects.filter(pk=view.request.data["service_id"]).first()
                if service:
                    service_display_name = _get_service_name(service)

            if service_display_name:
                audit_operation.name = audit_operation.name.format(
                    service_display_name=service_display_name,
                )

            obj = Cluster.objects.get(pk=cluster_pk)
            audit_object = get_or_create_audit_obj(
                object_id=cluster_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Cluster,
            )

        case ["cluster", cluster_pk, "service", service_pk]:
            audit_operation = AuditOperation(
                name="{service_display_name} service removed",
                operation_type=AuditLogOperationType.Update,
            )

            service_display_name = None
            if deleted_obj:
                if isinstance(deleted_obj, ClusterObject):
                    deleted_obj: ClusterObject
                    service_display_name = deleted_obj.display_name
                else:
                    service = ClusterObject.objects.filter(pk=service_pk).first()
                    if service:
                        service_display_name = _get_service_name(service)

            if service_display_name:
                audit_operation.name = audit_operation.name.format(
                    service_display_name=service_display_name,
                )

            obj = Cluster.objects.get(pk=cluster_pk)
            audit_object = get_or_create_audit_obj(
                object_id=cluster_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Cluster,
            )

        case ["cluster", cluster_pk, "service", service_pk, "bind"]:
            cluster = Cluster.objects.get(pk=cluster_pk)
            service = ClusterObject.objects.get(pk=service_pk)
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Service.capitalize()} bound to "
                f"{cluster.name}/{_get_service_name(service)}",
                operation_type=AuditLogOperationType.Update,
            )
            audit_object = get_or_create_audit_obj(
                object_id=service_pk,
                object_name=service.name,
                object_type=AuditObjectType.Service,
            )

        case ["cluster", cluster_pk, "service", service_pk, "bind", _]:
            cluster = Cluster.objects.get(pk=cluster_pk)
            service = ClusterObject.objects.get(pk=service_pk)
            audit_operation = AuditOperation(
                name=f"{cluster.name}/{_get_service_name(service)} unbound",
                operation_type=AuditLogOperationType.Update,
            )
            audit_object = get_or_create_audit_obj(
                object_id=service_pk,
                object_name=service.name,
                object_type=AuditObjectType.Service,
            )

        case ["cluster", _, "service", service_pk, "config", "history"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Service.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = ClusterObject.objects.get(pk=service_pk)
            audit_object = get_or_create_audit_obj(
                object_id=service_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Service,
            )

        case ["cluster", _, "service", service_pk, "import"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Service.capitalize()} "
                f"import {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = ClusterObject.objects.get(pk=service_pk)
            audit_object = get_or_create_audit_obj(
                object_id=service_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Service,
            )

        case ["cluster", _, "service", _, "component", component_pk, "config", "history"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Component.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = ServiceComponent.objects.get(pk=component_pk)
            audit_object = get_or_create_audit_obj(
                object_id=component_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Component,
            )

        case ["cluster", cluster_pk, "bind"]:
            obj = Cluster.objects.get(pk=cluster_pk)
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Cluster.capitalize()} bound to "
                f"{obj.name}/{{service_display_name}}",
                operation_type=AuditLogOperationType.Update,
            )
            audit_object = get_or_create_audit_obj(
                object_id=cluster_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Cluster,
            )

            service = None
            if response and response.data and response.data.get("export_service_id"):
                service = ClusterObject.objects.filter(
                    pk=response.data["export_service_id"],
                ).first()

            if "export_service_id" in view.request.data:
                service = ClusterObject.objects.filter(
                    pk=view.request.data["export_service_id"],
                ).first()

            if service:
                audit_operation.name = audit_operation.name.format(
                    service_display_name=_get_service_name(service),
                )

        case ["cluster", cluster_pk, "bind", bind_pk]:
            obj = Cluster.objects.get(pk=cluster_pk)
            audit_operation = AuditOperation(
                name=f"{obj.name}/{{service_display_name}} unbound",
                operation_type=AuditLogOperationType.Update,
            )

            service_display_name = ""
            if deleted_obj:
                if isinstance(deleted_obj, ClusterObject):
                    deleted_obj: ClusterObject
                    service_display_name = _get_service_name(deleted_obj)
                else:
                    bind = ClusterBind.objects.filter(pk=bind_pk).first()
                    if bind and bind.source_service:
                        service_display_name = _get_service_name(bind.source_service)

            audit_operation.name = audit_operation.name.format(
                service_display_name=service_display_name,
            )

            audit_object = get_or_create_audit_obj(
                object_id=cluster_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Cluster,
            )

        case (
            ["cluster", cluster_pk, "config", "history"]
            | ["cluster", cluster_pk, "config", "history", _, "restore"]
        ):
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Cluster.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = Cluster.objects.get(pk=cluster_pk)
            audit_object = get_or_create_audit_obj(
                object_id=cluster_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Cluster,
            )

        case ["cluster", _, "host", host_pk, "config", "history", _, "restore"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Host.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = Host.objects.get(pk=host_pk)
            audit_object = get_or_create_audit_obj(
                object_id=host_pk,
                object_name=obj.fqdn,
                object_type=AuditObjectType.Host,
            )

        case [
            "cluster",
            _,
            "service",
            _,
            "component",
            component_pk,
            "config",
            "history",
            _,
            "restore",
        ]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Component.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = ServiceComponent.objects.get(pk=component_pk)
            audit_object = get_or_create_audit_obj(
                object_id=component_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Component,
            )

        case ["cluster", _, "service", service_pk, "config", "history", _, "restore"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Service.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = ClusterObject.objects.get(pk=service_pk)
            audit_object = get_or_create_audit_obj(
                object_id=service_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Service,
            )

        case ["cluster", _, "host", host_pk, "config", "history"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Host.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = Host.objects.get(pk=host_pk)
            audit_object = get_or_create_audit_obj(
                object_id=host_pk,
                object_name=obj.fqdn,
                object_type=AuditObjectType.Host,
            )

        case ["config-log"]:
            audit_operation = AuditOperation(
                name=f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )

            config = None
            if response:
                config = response.data.serializer.instance.obj_ref
            elif view.request.data.get("obj_ref"):
                config = ObjectConfig.objects.filter(pk=view.request.data["obj_ref"]).first()

            if config:
                object_type = ContentType.objects.get_for_model(config.object).name
                object_type = _get_obj_type(object_type)

                if object_type == "host":
                    object_name = config.object.fqdn
                else:
                    object_name = config.object.name

                audit_object = get_or_create_audit_obj(
                    object_id=config.object.pk,
                    object_name=object_name,
                    object_type=object_type,
                )
                if object_type == "adcm":
                    object_type = "ADCM"
                else:
                    object_type = object_type.capitalize()

                operation_name = f"{object_type} {audit_operation.name}"
            else:
                audit_object = None
                operation_name = audit_operation.name

        case ["group-config", group_config_pk, "config", _, "config-log"]:
            audit_operation = AuditOperation(
                name=f"configuration group {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )

            config = None
            if response:
                config = response.data.serializer.instance.obj_ref
                if getattr(config, "group_config", None):
                    config = config.group_config
            elif view.request.data.get("obj_ref"):
                config = ObjectConfig.objects.filter(pk=view.request.data["obj_ref"]).first()

            if not config:
                config = GroupConfig.objects.filter(pk=group_config_pk).first()

            if config:
                object_type = ContentType.objects.get_for_model(config.object).name
                object_type = _get_obj_type(object_type)

                if object_type == "host":
                    object_name = config.object.fqdn
                else:
                    object_name = config.object.name

                audit_object = get_or_create_audit_obj(
                    object_id=config.object.pk,
                    object_name=object_name,
                    object_type=object_type,
                )
                object_type = object_type.capitalize()
                if isinstance(config, GroupConfig):
                    object_type = config.name

                operation_name = f"{object_type} {audit_operation.name}"
            else:
                audit_object = None
                operation_name = audit_operation.name

        case ["group-config"]:
            if view.action == "create":
                operation_type = AuditLogOperationType.Create
            elif view.action in {"update", "partial_update"}:
                operation_type = AuditLogOperationType.Update
            else:
                operation_type = AuditLogOperationType.Delete

            audit_operation = AuditOperation(
                name=f"configuration group {operation_type}d",
                operation_type=operation_type,
            )
            if response:
                if view.action == "destroy":
                    deleted_obj: GroupConfig
                    obj = deleted_obj
                else:
                    obj = response.data.serializer.instance

                object_type = _get_obj_type(obj.object_type.name)
                audit_object = get_or_create_audit_obj(
                    object_id=obj.object.id,
                    object_name=obj.object.name,
                    object_type=object_type,
                )
                operation_name = f"{obj.name} {audit_operation.name}"
            else:
                audit_object = None
                operation_name = audit_operation.name

        case ["group-config", group_config_pk]:
            if view.action in {"update", "partial_update"}:
                operation_type = AuditLogOperationType.Update
            else:
                operation_type = AuditLogOperationType.Delete

            audit_operation = AuditOperation(
                name=f"configuration group {operation_type}d",
                operation_type=operation_type,
            )
            if response:
                if view.action == "destroy":
                    deleted_obj: GroupConfig
                    obj = deleted_obj
                else:
                    obj = response.data.serializer.instance
            else:
                obj = GroupConfig.objects.filter(pk=group_config_pk).first()

            if obj:
                object_type = _get_obj_type(obj.object_type.name)
                audit_object = get_or_create_audit_obj(
                    object_id=obj.object.id,
                    object_name=obj.object.name,
                    object_type=object_type,
                )
                operation_name = f"{obj.name} {audit_operation.name}"
            else:
                audit_object = None
                operation_name = audit_operation.name

        case ["group-config", config_group_pk, "host"]:
            config_group = GroupConfig.objects.get(pk=config_group_pk)
            audit_operation = AuditOperation(
                name=f"host added to {config_group.name} configuration group",
                operation_type=AuditLogOperationType.Update,
            )
            object_type = _get_obj_type(config_group.object_type.name)
            audit_object = get_or_create_audit_obj(
                object_id=config_group.pk,
                object_name=config_group.object.name,
                object_type=object_type,
            )

            fqdn = None
            if response:
                fqdn = response.data["fqdn"]
            elif "id" in view.request.data:
                host = Host.objects.filter(pk=view.request.data["id"]).first()
                if host:
                    fqdn = host.fqdn

            if fqdn:
                audit_operation.name = f"{fqdn} {audit_operation.name}"

            operation_name = audit_operation.name

        case ["group-config", config_group_pk, "host", host_pk]:
            config_group = GroupConfig.objects.get(pk=config_group_pk)
            obj = Host.objects.get(pk=host_pk)
            audit_operation = AuditOperation(
                name=f"{obj.fqdn} host removed from {config_group.name} configuration group",
                operation_type=AuditLogOperationType.Update,
            )
            object_type = _get_obj_type(config_group.object_type.name)
            audit_object = get_or_create_audit_obj(
                object_id=config_group.pk,
                object_name=config_group.object.name,
                object_type=object_type,
            )

        case ["rbac", "group"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Group.capitalize()} " f"{AuditLogOperationType.Create}d",
                operation_type=AuditLogOperationType.Create,
            )
            audit_object = _get_audit_object_from_resp(
                response=response,
                obj_type=AuditObjectType.Group,
            )

        case ["rbac", "group", group_pk]:
            if view.action == "destroy":
                deleted_obj: Group
                operation_type = AuditLogOperationType.Delete
                obj = deleted_obj
            else:
                operation_type = AuditLogOperationType.Update
                obj = Group.objects.get(pk=group_pk)

            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Group.capitalize()} " f"{operation_type}d",
                operation_type=operation_type,
            )
            audit_object = get_or_create_audit_obj(
                object_id=group_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Group,
            )

        case ["rbac", "policy"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Policy.capitalize()} " f"{AuditLogOperationType.Create}d",
                operation_type=AuditLogOperationType.Create,
            )
            audit_object = _get_audit_object_from_resp(
                response=response,
                obj_type=AuditObjectType.Policy,
            )

        case ["rbac", "policy", policy_pk]:
            if view.action == "destroy":
                deleted_obj: Policy
                operation_type = AuditLogOperationType.Delete
                obj = deleted_obj
            else:
                operation_type = AuditLogOperationType.Update
                obj = Policy.objects.get(pk=policy_pk)

            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Policy.capitalize()} " f"{operation_type}d",
                operation_type=operation_type,
            )
            audit_object = get_or_create_audit_obj(
                object_id=policy_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Policy,
            )

        case ["rbac", "role"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Role.capitalize()} " f"{AuditLogOperationType.Create}d",
                operation_type=AuditLogOperationType.Create,
            )
            audit_object = _get_audit_object_from_resp(
                response=response,
                obj_type=AuditObjectType.Role,
            )

        case ["rbac", "role", role_pk]:
            if view.action == "destroy":
                deleted_obj: Role
                operation_type = AuditLogOperationType.Delete
                obj = deleted_obj
            else:
                operation_type = AuditLogOperationType.Update
                obj = Role.objects.get(pk=role_pk)

            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Role.capitalize()} " f"{operation_type}d",
                operation_type=operation_type,
            )
            audit_object = get_or_create_audit_obj(
                object_id=role_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Role,
            )

        case ["rbac", "user"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.User.capitalize()} " f"{AuditLogOperationType.Create}d",
                operation_type=AuditLogOperationType.Create,
            )
            if response:
                audit_object = get_or_create_audit_obj(
                    object_id=response.data["id"],
                    object_name=response.data["username"],
                    object_type=AuditObjectType.User,
                )
            else:
                audit_object = None

        case ["rbac", "user", user_pk]:
            if view.action == "destroy":
                deleted_obj: User
                operation_type = AuditLogOperationType.Delete
                obj = deleted_obj
            else:
                operation_type = AuditLogOperationType.Update
                obj = User.objects.get(pk=user_pk)

            audit_operation = AuditOperation(
                name=f"{AuditObjectType.User.capitalize()} " f"{operation_type}d",
                operation_type=operation_type,
            )
            audit_object = get_or_create_audit_obj(
                object_id=user_pk,
                object_name=obj.username,
                object_type=AuditObjectType.User,
            )

        case ["host", host_pk] | ["provider", _, "host", host_pk]:
            deleted_obj: Host
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Host.capitalize()} " f"{AuditLogOperationType.Delete}d",
                operation_type=AuditLogOperationType.Delete,
            )
            object_name = None
            if isinstance(deleted_obj, Host):
                object_name = deleted_obj.fqdn
            else:
                host = Host.objects.filter(pk=host_pk).first()
                if host:
                    object_name = host.fqdn

            if object_name:
                audit_object = get_or_create_audit_obj(
                    object_id=host_pk,
                    object_name=object_name,
                    object_type=AuditObjectType.Host,
                )
            else:
                audit_object = None

        case ["host"] | ["provider", _, "host"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Host.capitalize()} " f"{AuditLogOperationType.Create}d",
                operation_type=AuditLogOperationType.Create,
            )
            if response and response.data and response.data.get("id") and response.data.get("fqdn"):
                audit_object = get_or_create_audit_obj(
                    object_id=response.data["id"],
                    object_name=response.data["fqdn"],
                    object_type=AuditObjectType.Host,
                )
            else:
                audit_object = None

        case ["provider", _, "host", host_pk, "config", "history"]:
            obj = Host.objects.get(pk=host_pk)
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Host.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            audit_object = get_or_create_audit_obj(
                object_id=obj.pk,
                object_name=obj.fqdn,
                object_type=AuditObjectType.Host,
            )

        case ["provider"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Provider.capitalize()} " f"{AuditLogOperationType.Create}d",
                operation_type=AuditLogOperationType.Create,
            )
            if response:
                audit_object = _get_audit_object_from_resp(
                    response=response,
                    obj_type=AuditObjectType.Provider,
                )
            else:
                audit_object = None

        case ["provider", provider_pk]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Provider.capitalize()} " f"{AuditLogOperationType.Delete}d",
                operation_type=AuditLogOperationType.Delete,
            )
            if isinstance(deleted_obj, HostProvider):
                audit_object = get_or_create_audit_obj(
                    object_id=provider_pk,
                    object_name=deleted_obj.name,
                    object_type=AuditObjectType.Provider,
                )
            else:
                audit_object = None

        case ["provider", provider_pk, "config", "history"]:
            obj = HostProvider.objects.get(pk=provider_pk)
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Provider.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            audit_object = get_or_create_audit_obj(
                object_id=provider_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Provider,
            )

        case (
            ["host", host_pk, "config", "history"]
            | ["host", host_pk, "config", "history", _, "restore"]
        ):
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Host.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = Host.objects.get(pk=host_pk)
            audit_object = get_or_create_audit_obj(
                object_id=host_pk,
                object_name=obj.fqdn,
                object_type=AuditObjectType.Host,
            )

        case ["service", _]:
            deleted_obj: ClusterObject
            audit_operation = AuditOperation(
                name=f"{deleted_obj.display_name} service removed",
                operation_type=AuditLogOperationType.Update,
            )
            audit_object = get_or_create_audit_obj(
                object_id=deleted_obj.cluster.pk,
                object_name=deleted_obj.cluster.name,
                object_type=AuditObjectType.Cluster,
            )

        case ["service", service_pk, "import"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Service.capitalize()} "
                f"import {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = ClusterObject.objects.get(pk=service_pk)
            audit_object = get_or_create_audit_obj(
                object_id=service_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Service,
            )

        case ["service", service_pk, "bind"]:
            obj = ClusterObject.objects.get(pk=service_pk)
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Service.capitalize()} "
                f"bound to {{export_cluster_name}}/{_get_service_name(obj)}",
                operation_type=AuditLogOperationType.Update,
            )

            export_cluster_name = None
            if response and response.data:
                export_cluster_name = response.data["export_cluster_name"]
            elif "export_cluster_id" in view.request.data:
                cluster = Cluster.objects.filter(pk=view.request.data["export_cluster_id"]).first()
                if cluster:
                    export_cluster_name = cluster.name

            if export_cluster_name:
                audit_operation.name = audit_operation.name.format(
                    export_cluster_name=export_cluster_name,
                )

            audit_object = get_or_create_audit_obj(
                object_id=service_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Service,
            )

        case ["service", service_pk, "bind", _]:
            obj = ClusterObject.objects.get(pk=service_pk)
            audit_operation = AuditOperation(
                name=f"{{export_cluster_name}}/{_get_service_name(obj)} unbound",
                operation_type=AuditLogOperationType.Update,
            )

            export_cluster_name = ""
            if deleted_obj:
                if isinstance(deleted_obj, tuple):
                    export_cluster_name = deleted_obj[0].cluster.name
                else:
                    deleted_obj: ClusterObject
                    export_cluster_name = deleted_obj.cluster.name

            audit_operation.name = audit_operation.name.format(
                export_cluster_name=export_cluster_name,
            )

            audit_object = get_or_create_audit_obj(
                object_id=service_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Service,
            )

        case (
            ["service", _, "component", component_pk, "config", "history"]
            | ["service", _, "component", component_pk, "config", "history", _, "restore"]
        ):
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Component.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = ServiceComponent.objects.get(pk=component_pk)
            audit_object = get_or_create_audit_obj(
                object_id=component_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Component,
            )

        case (
            ["service", service_pk, "config", "history"]
            | ["service", service_pk, "config", "history", _, "restore"]
        ):
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Service.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = ClusterObject.objects.get(pk=service_pk)
            audit_object = get_or_create_audit_obj(
                object_id=service_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Service,
            )

        case ["component", component_pk, "config", "history", _, "restore"]:
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.Component.capitalize()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = ServiceComponent.objects.get(pk=component_pk)
            audit_object = get_or_create_audit_obj(
                object_id=component_pk,
                object_name=obj.name,
                object_type=AuditObjectType.Component,
            )

        case (
            ["adcm", adcm_pk, "config", "history"]
            | ["adcm", adcm_pk, "config", "history", _, "restore"]
        ):
            audit_operation = AuditOperation(
                name=f"{AuditObjectType.ADCM.upper()} "
                f"configuration {AuditLogOperationType.Update}d",
                operation_type=AuditLogOperationType.Update,
            )
            obj = ADCM.objects.get(pk=adcm_pk)
            audit_object = get_or_create_audit_obj(
                object_id=adcm_pk,
                object_name=obj.name,
                object_type=AuditObjectType.ADCM,
            )

        case (
            [obj_type, obj_pk, "action", action_pk, "run"]
            | [_, _, obj_type, obj_pk, "action", action_pk, "run"]
        ):
            audit_operation = AuditOperation(
                name="{action_display_name} action launched",
                operation_type=AuditLogOperationType.Update,
            )

            action = Action.objects.filter(pk=action_pk).first()
            if action:
                audit_operation.name = audit_operation.name.format(
                    action_display_name=action.display_name
                )

            obj = PATH_STR_TO_OBJ_CLASS_MAP[obj_type].objects.filter(pk=obj_pk).first()
            if obj:
                if isinstance(obj, Host):
                    obj_name = obj.fqdn
                else:
                    obj_name = obj.name
                audit_object = get_or_create_audit_obj(
                    object_id=obj_pk,
                    object_name=obj_name,
                    object_type=AUDIT_OBJECT_TYPE_TO_MODEL_MAP[PATH_STR_TO_OBJ_CLASS_MAP[obj_type]],
                )
            else:
                audit_object = None

        case [obj_type, obj_pk, "upgrade", upgrade_pk, "do"]:
            upgrade = Upgrade.objects.filter(pk=upgrade_pk).first()
            if not (upgrade and upgrade.action):
                return None, None, None

            audit_operation = AuditOperation(
                name=f"{upgrade.action.display_name} action launched",
                operation_type=AuditLogOperationType.Update,
            )

            obj = PATH_STR_TO_OBJ_CLASS_MAP[obj_type].objects.filter(pk=obj_pk).first()
            if obj:
                audit_object = get_or_create_audit_obj(
                    object_id=obj_pk,
                    object_name=obj.name,
                    object_type=AUDIT_OBJECT_TYPE_TO_MODEL_MAP[PATH_STR_TO_OBJ_CLASS_MAP[obj_type]],
                )
            else:
                audit_object = None

        case ["task", task_pk, action] | ["task", task_pk, action]:
            audit_operation, audit_object = _task_case(task_pk, action)

        case _:
            return None, None, None

    if not operation_name and audit_operation:
        operation_name = audit_operation.name

    return audit_operation, audit_object, operation_name
