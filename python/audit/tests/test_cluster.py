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

from datetime import datetime
from pathlib import Path

from audit.models import (
    AuditLog,
    AuditLogOperationResult,
    AuditLogOperationType,
    AuditObject,
    AuditObjectType,
)
from cm.models import (
    Bundle,
    Cluster,
    ClusterBind,
    ClusterObject,
    ConfigLog,
    Host,
    HostComponent,
    HostProvider,
    ObjectConfig,
    Prototype,
    PrototypeExport,
    PrototypeImport,
    ServiceComponent,
)
from django.conf import settings
from django.urls import reverse
from rest_framework.response import Response

from adcm.tests.base import APPLICATION_JSON, BaseTestCase


class TestCluster(BaseTestCase):
    # pylint: disable=too-many-instance-attributes,too-many-public-methods

    def setUp(self) -> None:
        super().setUp()

        self.bundle = Bundle.objects.create()
        self.test_cluster_name = "test_cluster"
        self.cluster_prototype = Prototype.objects.create(bundle=self.bundle, type="cluster")
        PrototypeImport.objects.create(prototype=self.cluster_prototype)
        config = ObjectConfig.objects.create(current=1, previous=1)
        ConfigLog.objects.create(obj_ref=config, config="{}")
        self.cluster = Cluster.objects.create(
            prototype=self.cluster_prototype, name="test_cluster_2", config=config
        )
        self.service_prototype = Prototype.objects.create(
            bundle=self.bundle,
            type="service",
            display_name="test_service",
        )
        PrototypeExport.objects.create(prototype=self.service_prototype)
        self.service = ClusterObject.objects.create(
            prototype=self.service_prototype,
            cluster=self.cluster,
        )

        provider_prototype = Prototype.objects.create(bundle=self.bundle, type="provider")
        provider = HostProvider.objects.create(
            name="test_provider",
            prototype=provider_prototype,
        )
        host_prototype = Prototype.objects.create(bundle=self.bundle, type="host")
        self.host = Host.objects.create(
            fqdn="test_fqdn",
            prototype=host_prototype,
            provider=provider,
            config=config,
        )

    def check_log(
        self,
        log: AuditLog,
        obj: Cluster | Host | HostComponent | ClusterObject | ServiceComponent,
        obj_type: AuditObjectType,
        operation_name: str,
        operation_type: AuditLogOperationType,
    ) -> None:
        if isinstance(obj, Host):
            obj_name = obj.fqdn
        else:
            obj_name = obj.name

        assert log.audit_object.object_id == obj.pk
        assert log.audit_object.object_name == obj_name
        assert log.audit_object.object_type == obj_type
        assert not log.audit_object.is_deleted
        assert log.operation_name == operation_name
        assert log.operation_type == operation_type
        assert log.operation_result == AuditLogOperationResult.Success
        assert isinstance(log.operation_time, datetime)
        assert log.user.pk == self.test_user.pk
        assert isinstance(log.object_changes, dict)

    def check_cluster_update_config(self, log: AuditLog) -> None:
        self.check_log(
            log=log,
            obj=self.cluster,
            obj_type=AuditObjectType.Cluster,
            operation_name="Cluster configuration updated",
            operation_type=AuditLogOperationType.Update,
        )

    def create_cluster(self, bundle_id: int, name: str, prototype_id: int):
        return self.client.post(
            path=reverse("cluster"),
            data={
                "bundle_id": bundle_id,
                "display_name": f"{name}_display",
                "name": name,
                "prototype_id": prototype_id,
            },
        )

    def test_create(self):
        res: Response = self.create_cluster(
            bundle_id=self.bundle.pk,
            name=self.test_cluster_name,
            prototype_id=self.cluster_prototype.pk,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=Cluster.objects.get(pk=res.data["id"]),
            obj_type=AuditObjectType.Cluster,
            operation_name="Cluster created",
            operation_type=AuditLogOperationType.Create,
        )

        self.create_cluster(
            bundle_id=self.bundle.pk,
            name=self.test_cluster_name,
            prototype_id=self.cluster_prototype.pk,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        assert not log.audit_object
        assert log.operation_name == "Cluster created"
        assert log.operation_type == AuditLogOperationType.Create
        assert log.operation_result == AuditLogOperationResult.Fail
        assert isinstance(log.operation_time, datetime)
        assert log.user.pk == self.test_user.pk
        assert isinstance(log.object_changes, dict)

    def test_delete_two_clusters(self):
        cluster_bundle_filename = "test_cluster_bundle.tar"
        provider_bundle_filename = "test_provider_bundle.tar"

        with open(
            Path(settings.BASE_DIR, "python/audit/tests/files", cluster_bundle_filename),
            encoding="utf-8",
        ) as f:
            self.client.post(
                path=reverse("upload-bundle"),
                data={"file": f},
            )

        cluster_bundle_res: Response = self.client.post(
            path=reverse("load-bundle"),
            data={"bundle_file": cluster_bundle_filename},
        )

        with open(
            Path(settings.BASE_DIR, "python/audit/tests/files", provider_bundle_filename),
            encoding="utf-8",
        ) as f:
            self.client.post(
                path=reverse("upload-bundle"),
                data={"file": f},
            )

        provider_bundle_res: Response = self.client.post(
            path=reverse("load-bundle"),
            data={"bundle_file": provider_bundle_filename},
        )

        cluster_prototype = Prototype.objects.create(
            bundle_id=cluster_bundle_res.data["id"], type="cluster"
        )
        cluster_1_res: Response = self.create_cluster(
            bundle_id=cluster_bundle_res.data["id"],
            name="new_test_cluster_1",
            prototype_id=cluster_prototype.pk,
        )
        self.create_cluster(
            bundle_id=cluster_bundle_res.data["id"],
            name="new_test_cluster_2",
            prototype_id=cluster_prototype.pk,
        )

        provider_prototype = Prototype.objects.create(
            bundle_id=provider_bundle_res.data["id"], type="provider"
        )
        provider_res: Response = self.client.post(
            path=reverse("provider"),
            data={
                "name": "new_test_provider",
                "prototype_id": provider_prototype.pk,
            },
        )

        host_prototype = Prototype.objects.create(
            bundle_id=provider_bundle_res.data["id"], type="host"
        )
        host_1_res: Response = self.client.post(
            path=reverse("host"),
            data={
                "prototype_id": host_prototype.pk,
                "provider_id": provider_res.data["id"],
                "fqdn": "test_fqdn_1",
            },
        )
        self.client.post(
            path=reverse("host"),
            data={
                "prototype_id": host_prototype.pk,
                "provider_id": provider_res.data["id"],
                "fqdn": "test_fqdn_2",
            },
        )

        self.client.post(
            path=reverse("host", kwargs={"cluster_id": cluster_1_res.data["id"]}),
            data={"host_id": host_1_res.data["id"]},
            content_type=APPLICATION_JSON,
        )

        service_prototype = Prototype.objects.create(
            bundle=self.bundle,
            type="service",
            display_name="new_test_service",
        )
        service = ClusterObject.objects.create(
            prototype=service_prototype,
            cluster_id=cluster_1_res.data["id"],
        )
        self.client.post(
            path=reverse("service", kwargs={"cluster_id": cluster_1_res.data["id"]}),
            data={
                "service_id": service.pk,
                "prototype_id": service_prototype.pk,
            },
            content_type=APPLICATION_JSON,
        )

        self.assertFalse(AuditObject.objects.filter(is_deleted=True))

        self.client.delete(
            path=reverse("cluster-details", kwargs={"cluster_id": cluster_1_res.data["id"]})
        )

        self.assertEqual(AuditObject.objects.filter(is_deleted=True).count(), 1)

    def test_delete(self):
        self.client.delete(path=reverse("cluster-details", kwargs={"cluster_id": self.cluster.pk}))

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.cluster,
            obj_type=AuditObjectType.Cluster,
            operation_name="Cluster deleted",
            operation_type=AuditLogOperationType.Delete,
        )

    def test_update(self):
        self.client.patch(
            path=reverse("cluster-details", kwargs={"cluster_id": self.cluster.pk}),
            data={"display_name": "test_cluster_another_display_name"},
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.cluster,
            obj_type=AuditObjectType.Cluster,
            operation_name="Cluster updated",
            operation_type=AuditLogOperationType.Update,
        )

    def test_bind_unbind(self):
        self.client.post(
            path=reverse("cluster-bind", kwargs={"cluster_id": self.cluster.pk}),
            data={
                "export_cluster_id": self.cluster.pk,
                "export_service_id": self.service.pk,
            },
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.cluster,
            obj_type=AuditObjectType.Cluster,
            operation_name=f"Cluster bound to {self.cluster.name}/{self.service.display_name}",
            operation_type=AuditLogOperationType.Update,
        )

        bind = ClusterBind.objects.first()
        self.client.delete(
            path=reverse(
                "cluster-bind-details", kwargs={"cluster_id": self.cluster.pk, "bind_id": bind.pk}
            ),
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.cluster,
            obj_type=AuditObjectType.Cluster,
            operation_name=f"{self.cluster.name}/{self.service.display_name} unbound",
            operation_type=AuditLogOperationType.Update,
        )

    def test_update_config(self):
        self.client.post(
            path=reverse("config-history", kwargs={"cluster_id": self.cluster.pk}),
            data={"config": {}},
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_cluster_update_config(log)

    def test_add_host(self):
        self.client.post(
            path=reverse("host", kwargs={"cluster_id": self.cluster.pk}),
            data={"host_id": self.host.pk},
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.cluster,
            obj_type=AuditObjectType.Cluster,
            operation_name=f"{self.host.fqdn} added",
            operation_type=AuditLogOperationType.Update,
        )

    def test_update_host_config(self):
        self.client.post(
            path=reverse(
                "config-history",
                kwargs={"cluster_id": self.cluster.pk, "host_id": self.host.pk},
            ),
            data={"config": {}},
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.host,
            obj_type=AuditObjectType.Host,
            operation_name="Host configuration updated",
            operation_type=AuditLogOperationType.Update,
        )

    def test_update_hostcomponent(self):
        service_component_prototype = Prototype.objects.create(bundle=self.bundle, type="component")
        service_component = ServiceComponent.objects.create(
            cluster=self.cluster,
            service=self.service,
            prototype=service_component_prototype,
        )
        hc = HostComponent.objects.create(
            cluster=self.cluster,
            host=self.host,
            service=self.service,
            component=service_component,
        )
        self.host.cluster = self.cluster
        self.host.save(update_fields=["cluster"])

        self.client.post(
            path=reverse("host-component", kwargs={"cluster_id": self.cluster.pk}),
            data={
                "hc": [
                    {
                        "component_id": hc.pk,
                        "host_id": self.host.pk,
                        "service_id": self.service.pk,
                    }
                ]
            },
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.cluster,
            obj_type=AuditObjectType.Cluster,
            operation_name="Host-Component map updated",
            operation_type=AuditLogOperationType.Update,
        )

    def test_import(self):
        self.client.post(
            path=reverse("cluster-import", kwargs={"cluster_id": self.cluster.pk}),
            data={"bind": []},
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.cluster,
            obj_type=AuditObjectType.Cluster,
            operation_name="Cluster import updated",
            operation_type=AuditLogOperationType.Update,
        )

    def test_add_service(self):
        cluster = Cluster.objects.create(prototype=self.cluster_prototype, name="test_cluster_3")
        self.client.post(
            path=reverse("service", kwargs={"cluster_id": cluster.pk}),
            data={
                "service_id": self.service.pk,
                "prototype_id": self.service_prototype.pk,
            },
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=cluster,
            obj_type=AuditObjectType.Cluster,
            operation_name="test_service service added",
            operation_type=AuditLogOperationType.Update,
        )

    def test_delete_service(self):
        self.client.delete(
            path=reverse(
                "service-details",
                kwargs={"cluster_id": self.cluster.pk, "service_id": self.service.pk},
            ),
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.cluster,
            obj_type=AuditObjectType.Cluster,
            operation_name=f"{self.service.display_name} service removed",
            operation_type=AuditLogOperationType.Update,
        )

    def test_bind_unbind_service(self):
        bundle = Bundle.objects.create(name="test_bundle_2")
        cluster_prototype = Prototype.objects.create(bundle=bundle, type="cluster")
        cluster = Cluster.objects.create(prototype=cluster_prototype, name="test_cluster_3")
        PrototypeExport.objects.create(prototype=cluster_prototype)
        PrototypeImport.objects.create(prototype=self.service_prototype)

        self.client.post(
            path=reverse(
                "service-bind",
                kwargs={"cluster_id": cluster.pk, "service_id": self.service.pk},
            ),
            data={"export_cluster_id": cluster.pk},
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.service,
            obj_type=AuditObjectType.Service,
            operation_name="Service bound to test_cluster_3/test_service",
            operation_type=AuditLogOperationType.Update,
        )

        bind = ClusterBind.objects.first()
        self.client.delete(
            reverse(
                "service-bind-details",
                kwargs={
                    "cluster_id": cluster.pk,
                    "service_id": self.service.pk,
                    "bind_id": bind.pk,
                },
            ),
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.service,
            obj_type=AuditObjectType.Service,
            operation_name="test_cluster_3/test_service unbound",
            operation_type=AuditLogOperationType.Update,
        )

    def test_update_component_config(self):
        config = ObjectConfig.objects.create(current=2, previous=2)
        ConfigLog.objects.create(obj_ref=config, config="{}")
        prototype = Prototype.objects.create(bundle=self.bundle, type="component")
        component = ServiceComponent.objects.create(
            cluster=self.cluster,
            service=self.service,
            prototype=prototype,
            config=config,
        )
        self.client.post(
            path=reverse(
                "config-history",
                kwargs={
                    "cluster_id": self.cluster.pk,
                    "service_id": self.service.pk,
                    "component_id": component.pk,
                },
            ),
            data={"config": {}},
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=component,
            obj_type=AuditObjectType.Component,
            operation_name="Component configuration updated",
            operation_type=AuditLogOperationType.Update,
        )

    def test_update_service_config(self):
        config = ObjectConfig.objects.create(current=2, previous=2)
        ConfigLog.objects.create(obj_ref=config, config="{}")
        self.service.config = config
        self.service.save(update_fields=["config"])
        self.client.post(
            path=reverse(
                "config-history",
                kwargs={
                    "cluster_id": self.cluster.pk,
                    "service_id": self.service.pk,
                },
            ),
            data={"config": {}},
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.service,
            obj_type=AuditObjectType.Service,
            operation_name="Service configuration updated",
            operation_type=AuditLogOperationType.Update,
        )

    def test_service_import(self):
        self.client.post(
            path=reverse(
                "service-import",
                kwargs={"cluster_id": self.cluster.pk, "service_id": self.service.pk},
            ),
            data={"bind": []},
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.service,
            obj_type=AuditObjectType.Service,
            operation_name="Service import updated",
            operation_type=AuditLogOperationType.Update,
        )

    def test_cluster_config_restore(self):
        self.client.patch(
            path=reverse(
                "config-history-version-restore",
                kwargs={"cluster_id": self.cluster.pk, "version": 1},
            ),
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_cluster_update_config(log)

    def test_host_config_restore(self):
        self.client.patch(
            path=reverse(
                "config-history-version-restore",
                kwargs={"cluster_id": self.cluster.pk, "host_id": self.host.pk, "version": 1},
            ),
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.host,
            obj_type=AuditObjectType.Host,
            operation_name="Host configuration updated",
            operation_type=AuditLogOperationType.Update,
        )

    def test_component_config_restore(self):
        component_prototype = Prototype.objects.create(bundle=self.bundle, type="component")
        config = ObjectConfig.objects.create(current=2, previous=2)
        ConfigLog.objects.create(obj_ref=config, config="{}")
        component = ServiceComponent.objects.create(
            prototype=component_prototype,
            cluster=self.cluster,
            service=self.service,
            config=config,
        )
        self.client.patch(
            path=reverse(
                "config-history-version-restore",
                kwargs={
                    "cluster_id": self.cluster.pk,
                    "service_id": self.service.pk,
                    "component_id": component.pk,
                    "version": 2,
                },
            ),
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=component,
            obj_type=AuditObjectType.Component,
            operation_name="Component configuration updated",
            operation_type=AuditLogOperationType.Update,
        )

    def test_service_config_restore(self):
        config = ObjectConfig.objects.create(current=2, previous=2)
        ConfigLog.objects.create(obj_ref=config, config="{}")
        self.service.config = config
        self.service.save(update_fields=["config"])
        self.client.patch(
            path=reverse(
                "config-history-version-restore",
                kwargs={
                    "cluster_id": self.cluster.pk,
                    "service_id": self.service.pk,
                    "version": 2,
                },
            ),
            content_type=APPLICATION_JSON,
        )

        log: AuditLog = AuditLog.objects.order_by("operation_time").last()

        self.check_log(
            log=log,
            obj=self.service,
            obj_type=AuditObjectType.Service,
            operation_name="Service configuration updated",
            operation_type=AuditLogOperationType.Update,
        )
