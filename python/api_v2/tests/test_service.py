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

from typing import Callable
from unittest.mock import patch

from api_v2.tests.base import BaseAPITestCase
from cm.api import add_service_to_cluster
from cm.models import (
    Action,
    ADCMEntityStatus,
    ClusterObject,
    MaintenanceMode,
    ObjectType,
    Prototype,
)
from django.urls import reverse
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_201_CREATED, HTTP_204_NO_CONTENT


class TestServiceAPI(BaseAPITestCase):
    def setUp(self) -> None:
        super().setUp()

        add_service_to_cluster(
            cluster=self.cluster_1, proto=Prototype.objects.get(type=ObjectType.SERVICE, name="service_1")
        )
        self.service_2 = add_service_to_cluster(
            cluster=self.cluster_1, proto=Prototype.objects.get(type=ObjectType.SERVICE, name="service_2")
        )

        self.action = Action.objects.filter(prototype=self.service_2.prototype).first()

    def get_service_status_mock(self) -> Callable:
        def inner(service: ClusterObject) -> int:
            if service.pk == self.service_2.pk:
                return 0

            return 32

        return inner

    def test_list_success(self):
        response: Response = self.client.get(
            path=reverse(viewname="v2:service-list", kwargs={"cluster_pk": self.cluster_1.pk}),
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 2)

    def test_retrieve_success(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:service-detail", kwargs={"cluster_pk": self.cluster_1.pk, "pk": self.service_2.pk}
            ),
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["id"], self.service_2.pk)

    def test_delete_success(self):
        response: Response = self.client.delete(
            path=reverse(
                viewname="v2:service-detail", kwargs={"cluster_pk": self.cluster_1.pk, "pk": self.service_2.pk}
            ),
        )

        self.assertEqual(response.status_code, HTTP_204_NO_CONTENT)
        self.assertFalse(ClusterObject.objects.filter(pk=self.service_2.pk).exists())

    def test_create_success(self):
        manual_add_service_proto = Prototype.objects.get(type=ObjectType.SERVICE, name="service_3_manual_add")
        response: Response = self.client.post(
            path=reverse(viewname="v2:service-list", kwargs={"cluster_pk": self.cluster_1.pk}),
            data={"prototype": manual_add_service_proto.pk},
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)

    def test_filter_by_name_success(self):
        response: Response = self.client.get(
            path=reverse(viewname="v2:service-list", kwargs={"cluster_pk": self.cluster_1.pk}),
            data={"name": "service_1"},
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)

    def test_filter_by_status_success(self):
        with patch("api_v2.service.filters.get_service_status", new_callable=self.get_service_status_mock):
            response: Response = self.client.get(
                path=reverse(viewname="v2:service-list", kwargs={"cluster_pk": self.cluster_1.pk}),
                data={"status": ADCMEntityStatus.UP},
            )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(len(response.json()["results"]), 1)
        self.assertEqual(response.json()["results"][0]["id"], self.service_2.pk)

    def test_limit_offset_success(self):
        response: Response = self.client.get(
            path=reverse(viewname="v2:service-list", kwargs={"cluster_pk": self.cluster_1.pk}),
            data={"limit": 1, "offset": 1},
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(len(response.json()["results"]), 1)

    def test_change_mm(self):
        response: Response = self.client.post(
            path=reverse(
                viewname="v2:service-maintenance-mode",
                kwargs={"cluster_pk": self.cluster_1.pk, "pk": self.service_2.pk},
            ),
            data={"maintenance_mode": MaintenanceMode.ON},
        )

        self.assertEqual(response.status_code, HTTP_200_OK)

    def test_action_list_success(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:service-action-list",
                kwargs={"cluster_pk": self.cluster_1.pk, "service_pk": self.service_2.pk},
            ),
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertGreater(len(response.json()), 0)

    def test_action_retrieve_success(self):
        response: Response = self.client.get(
            path=reverse(
                viewname="v2:service-action-detail",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_2.pk,
                    "pk": self.action.pk,
                },
            ),
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertTrue(response.json())

    def test_action_run_success(self):
        response: Response = self.client.post(
            path=reverse(
                viewname="v2:service-action-run",
                kwargs={
                    "cluster_pk": self.cluster_1.pk,
                    "service_pk": self.service_2.pk,
                    "pk": self.action.pk,
                },
            ),
            data={"host_component_map": {}, "config": {}, "attr": {}, "is_verbose": False},
        )

        self.assertEqual(response.status_code, HTTP_200_OK)
