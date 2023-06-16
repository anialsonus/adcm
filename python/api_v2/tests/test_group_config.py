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

from api_v2.tests.base import BaseAPITestCase
from cm.models import GroupConfig, ServiceComponent
from django.contrib.contenttypes.models import ContentType
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_204_NO_CONTENT,
    HTTP_404_NOT_FOUND,
)


class BaseClusterGroupConfigTestCase(BaseAPITestCase):
    def setUp(self) -> None:
        super().setUp()

        self.cluster_1_group_config = GroupConfig.objects.create(
            name="group_config",
            object_type=ContentType.objects.get_for_model(self.cluster_1),
            object_id=self.cluster_1.pk,
        )
        self.host_fqdn = "host"
        self.host = self.add_host(bundle=self.provider_bundle, provider=self.provider, fqdn=self.host_fqdn)
        self.cluster_1_group_config.hosts.add(self.host)
        self.new_host_fqdn = "new_host"
        self.new_host = self.add_host(bundle=self.provider_bundle, provider=self.provider, fqdn=self.new_host_fqdn)
        self.add_host_to_cluster(cluster=self.cluster_1, host=self.new_host)


class BaseServiceGroupConfigTestCase(BaseClusterGroupConfigTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.service_1 = self.add_service_to_cluster(service_name="service_1", cluster=self.cluster_1)
        self.service_1_group_config = GroupConfig.objects.create(
            name="service_1_group_config",
            object_type=ContentType.objects.get_for_model(self.service_1),
            object_id=self.service_1.pk,
        )
        self.service_1_group_config.hosts.add(self.host)
        self.host_for_service = self.add_host(
            bundle=self.provider_bundle, provider=self.provider, fqdn="host_for_service"
        )
        self.add_host_to_cluster(cluster=self.cluster_1, host=self.host_for_service)

        self.component_1 = ServiceComponent.objects.get(
            cluster=self.cluster_1, service=self.service_1, prototype__name="component_1"
        )
        self.add_hostcomponent_map(
            cluster=self.cluster_1,
            hc_map=[
                {
                    "host_id": self.host_for_service.pk,
                    "service_id": self.service_1.pk,
                    "component_id": self.component_1.pk,
                }
            ],
        )


class TestClusterGroupConfig(BaseClusterGroupConfigTestCase):
    def test_list_success(self):
        response: Response = self.client.get(
            path=reverse(viewname="v2:cluster-config-group-list", kwargs={"cluster_pk": self.cluster_1.pk})
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["id"], self.cluster_1_group_config.pk)

    def test_retrieve_success(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:cluster-config-group-detail",
                kwargs={"cluster_pk": self.cluster_1.pk, "pk": self.cluster_1_group_config.pk},
            )
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["id"], self.cluster_1_group_config.pk)

    def test_create_success(self):
        response: Response = self.client.post(
            path=reverse(viewname="v2:cluster-config-group-list", kwargs={"cluster_pk": self.cluster_1.pk}),
            data={"name": "group-config-new", "description": "group-config-new"},
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)
        self.assertEqual(response.json()["name"], "group-config-new")

    def test_delete_success(self):
        response: Response = self.client.delete(
            path=reverse(
                viewname="v2:cluster-config-group-detail",
                kwargs={"cluster_pk": self.cluster_1.pk, "pk": self.cluster_1_group_config.pk},
            )
        )

        self.assertEqual(response.status_code, HTTP_204_NO_CONTENT)

    def test_list_hosts(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:cluster-config-group-hosts",
                kwargs={"cluster_pk": self.cluster_1.pk, "pk": self.cluster_1_group_config.pk},
            )
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)

    def test_add_hosts(self):
        response: Response = self.client.post(
            path=reverse(
                "v2:cluster-config-group-hosts",
                kwargs={"cluster_pk": self.cluster_1.pk, "pk": self.cluster_1_group_config.pk},
            ),
            data=[{"id": self.new_host.pk}],
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.json()[0]["name"], self.new_host.name)

    def test_host_candidates(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:cluster-config-group-host-candidates",
                kwargs={"cluster_pk": self.cluster_1.pk, "pk": self.cluster_1_group_config.pk},
            )
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["name"], self.new_host.name)


class TestServiceGroupConfig(BaseServiceGroupConfigTestCase):  # pylint: disable=too-many-ancestors
    def test_list_success(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:service-config-group-list",
                kwargs={"cluster_pk": self.cluster_1.pk, "service_pk": self.service_1.pk},
            )
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["id"], self.service_1_group_config.pk)

    def test_retrieve_success(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:service-config-group-detail",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "pk": self.service_1_group_config.pk,
                },
            )
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["id"], self.service_1_group_config.pk)

    def test_create_success(self):
        response: Response = self.client.post(
            path=reverse(
                viewname="v2:service-config-group-list",
                kwargs={"cluster_pk": self.cluster_1.pk, "service_pk": self.service_1.pk},
            ),
            data={"name": "service-group-config-new", "description": "service-group-config-new"},
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)
        self.assertEqual(response.json()["name"], "service-group-config-new")

    def test_delete_success(self):
        response: Response = self.client.delete(
            path=reverse(
                viewname="v2:service-config-group-detail",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "pk": self.service_1_group_config.pk,
                },
            )
        )
        self.assertEqual(response.status_code, HTTP_204_NO_CONTENT)

        response: Response = self.client.get(
            path=reverse(
                viewname="v2:service-config-group-detail",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "pk": self.service_1_group_config.pk,
                },
            )
        )
        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)

    def test_list_hosts(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:service-config-group-hosts",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "pk": self.service_1_group_config.pk,
                },
            )
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["name"], self.host.name)

    def test_add_hosts(self):
        response: Response = self.client.post(
            path=reverse(
                viewname="v2:service-config-group-hosts",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "pk": self.service_1_group_config.pk,
                },
            ),
            data=[{"id": self.host_for_service.pk}],
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.json()[0]["name"], self.host_for_service.name)

    def test_host_candidates(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:service-config-group-host-candidates",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "pk": self.service_1_group_config.pk,
                },
            )
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["name"], self.host_for_service.name)


class TestComponentGroupConfig(BaseServiceGroupConfigTestCase):  # pylint: disable=too-many-ancestors
    def setUp(self) -> None:
        super().setUp()

        self.component_1_group_config = GroupConfig.objects.create(
            name="component_1_group_config",
            object_type=ContentType.objects.get_for_model(self.component_1),
            object_id=self.component_1.pk,
        )
        self.component_1_group_config.hosts.add(self.host)

        self.host_for_component = self.add_host(
            bundle=self.provider_bundle, provider=self.provider, fqdn="host_for_component"
        )
        self.add_host_to_cluster(cluster=self.cluster_1, host=self.host_for_component)
        self.add_hostcomponent_map(
            cluster=self.cluster_1,
            hc_map=[
                {
                    "host_id": self.host_for_component.pk,
                    "service_id": self.service_1.pk,
                    "component_id": self.component_1.pk,
                }
            ],
        )

    def test_list_success(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:component-config-group-list",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "component_pk": self.component_1.pk,
                },
            )
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["id"], self.component_1_group_config.pk)

    def test_retrieve_success(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:component-config-group-detail",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "component_pk": self.component_1.pk,
                    "pk": self.component_1_group_config.pk,
                },
            )
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["id"], self.component_1_group_config.pk)

    def test_create_success(self):
        response: Response = self.client.post(
            path=reverse(
                viewname="v2:component-config-group-list",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "component_pk": self.component_1.pk,
                },
            ),
            data={"name": "component-group-config-new", "description": "component-group-config-new"},
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)
        self.assertEqual(response.json()["name"], "component-group-config-new")

    def test_delete_success(self):
        response: Response = self.client.delete(
            path=reverse(
                viewname="v2:component-config-group-detail",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "component_pk": self.component_1.pk,
                    "pk": self.component_1_group_config.pk,
                },
            )
        )
        self.assertEqual(response.status_code, HTTP_204_NO_CONTENT)

        response: Response = self.client.get(
            path=reverse(
                viewname="v2:component-config-group-detail",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "component_pk": self.component_1.pk,
                    "pk": self.component_1_group_config.pk,
                },
            )
        )
        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)

    def test_list_hosts(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:component-config-group-hosts",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "component_pk": self.component_1.pk,
                    "pk": self.component_1_group_config.pk,
                },
            )
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["name"], self.host.name)

    def test_add_hosts(self):
        response: Response = self.client.post(
            path=reverse(
                viewname="v2:component-config-group-hosts",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "component_pk": self.component_1.pk,
                    "pk": self.component_1_group_config.pk,
                },
            ),
            data=[{"id": self.host_for_component.pk}],
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.json()[0]["name"], self.host_for_component.name)

    def test_host_candidates(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:component-config-group-host-candidates",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_1.pk,
                    "component_pk": self.component_1.pk,
                    "pk": self.component_1_group_config.pk,
                },
            )
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["name"], self.host_for_component.name)
