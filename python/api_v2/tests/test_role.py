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

from django.db.models import Count
from rbac.models import Role
from rbac.services.group import create as create_group
from rbac.services.policy import policy_create
from rbac.services.role import role_create
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_204_NO_CONTENT,
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
)

from api_v2.tests.base import BaseAPITestCase


class TestRole(BaseAPITestCase):
    def setUp(self) -> None:
        super().setUp()

        self.view_cluster_config_role = Role.objects.get(name="View cluster configurations", built_in=True)
        self.edit_cluster_config_role = Role.objects.get(name="Edit cluster configurations", built_in=True)

        self.cluster_config_role = role_create(
            name="Change cluster config",
            display_name="Change cluster config",
            child=[self.view_cluster_config_role],
        )

    def test_retrieve_not_found_fail(self):
        response = (self.client.v2 / "rbac" / "roles" / str(self.get_non_existent_pk(model=Role))).get()

        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)

    def test_retrieve_hidden_not_found_fail(self):
        hidden_role = Role.objects.filter(type="hidden").first()
        response = self.client.v2[hidden_role].get()

        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)

    def test_retrieve_hidden_child_not_shown_success(self):
        role_with_hidden_children = (
            Role.objects.annotate(num_children=Count("child")).filter(num_children__gt=0, child__type="hidden").first()
        )
        response = self.client.v2[role_with_hidden_children].get()

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(len(response.json()["children"]), 0)

    def test_retrieve_success(self):
        response = self.client.v2[self.cluster_config_role].get()

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["id"], self.cluster_config_role.pk)

    def test_list_success(self):
        response = (self.client.v2 / "rbac" / "roles").get()

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertGreater(len(response.json()["results"]), 1)

    def test_create_success(self):
        response = (self.client.v2 / "rbac" / "roles").post(
            data={"display_name": "Edit cluster configuration", "children": [self.edit_cluster_config_role.pk]},
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)
        self.assertTrue(Role.objects.filter(id=response.json()["id"]).exists())

    def test_create_required_field_failed(self):
        response = (self.client.v2 / "rbac" / "roles").post(data={"display_name": "test"})

        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        self.assertDictEqual(
            response.json(), {"code": "BAD_REQUEST", "desc": "children - This field is required.;", "level": "error"}
        )

    def test_create_already_exists_failed(self):
        response = (self.client.v2 / "rbac" / "roles").post(
            data={
                "display_name": "Change cluster config",
                "children": [self.view_cluster_config_role.pk],
            },
        )

        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertDictEqual(
            response.json(),
            {
                "code": "ROLE_CREATE_ERROR",
                "desc": "A role with this name already exists",
                "level": "error",
            },
        )

    def test_update_required_filed_success(self):
        response = self.client.v2[self.cluster_config_role].patch(
            data={
                "display_name": "New change cluster config",
                "children": [self.edit_cluster_config_role.pk],
            },
        )

        self.cluster_config_role.refresh_from_db()

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual("New change cluster config", self.cluster_config_role.display_name)
        self.assertEqual([self.edit_cluster_config_role], list(self.cluster_config_role.child.all()))

    def test_partial_update_success(self):
        response = self.client.v2[self.cluster_config_role].patch(
            data={"display_name": "New change cluster config"},
        )

        self.cluster_config_role.refresh_from_db()

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual("New change cluster config", self.cluster_config_role.display_name)

    def test_update_built_in_failed(self):
        response = self.client.v2[self.view_cluster_config_role].patch(
            data={"built_in": False},
        )
        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertDictEqual(
            response.json(),
            {
                "code": "ROLE_UPDATE_ERROR",
                "desc": "Can't modify role View cluster configurations as it is auto created",
                "level": "error",
            },
        )

    def test_delete_success(self):
        response = self.client.v2[self.cluster_config_role].delete()

        self.assertEqual(response.status_code, HTTP_204_NO_CONTENT)
        self.assertFalse(Role.objects.filter(pk=self.cluster_config_role.pk).exists())

    def test_delete_failed(self):
        built_in_role = Role.objects.filter(built_in=True).exclude(type="hidden").first()

        response = self.client.v2[built_in_role].delete()

        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertDictEqual(
            response.json(),
            {"code": "ROLE_DELETE_ERROR", "desc": "It is forbidden to remove the built-in role.", "level": "error"},
        )

    def test_delete_role_in_policy_fail(self):
        child_role = Role.objects.get(name="View cluster configurations")
        group = create_group(name_to_display=f"Group for role `{child_role.name}`", user_set=[])
        custom_role_in_policy = role_create(display_name=f"Custom `{child_role.name}` role", child=[child_role])
        policy_create(
            name=f"Policy for role `{child_role.name}`",
            role=custom_role_in_policy,
            group=[group],
            object=[self.cluster_1],
        )

        response = self.client.v2[custom_role_in_policy].delete()

        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertDictEqual(
            response.json(),
            {"code": "ROLE_DELETE_ERROR", "desc": "Can't remove role that is used in policy.", "level": "error"},
        )

    def test_ordering_success(self):
        limit = 10

        response = (self.client.v2 / "rbac" / "roles").get(query={"ordering": "-displayName", "limit": limit})

        self.assertEqual(response.status_code, HTTP_200_OK)

        response_names = [role_data["displayName"] for role_data in response.json()["results"]]
        db_names = [role.display_name for role in Role.objects.order_by("-display_name").exclude(type="hidden")[:limit]]
        self.assertListEqual(response_names, db_names)

    def test_filtering_by_display_name_success(self):
        filter_name = "cReAtE"

        response = (self.client.v2 / "rbac" / "roles").get(query={"displayName": filter_name})

        self.assertEqual(response.status_code, HTTP_200_OK)

        response_pks = [role_data["id"] for role_data in response.json()["results"]]
        db_pks = [role.pk for role in Role.objects.filter(display_name__icontains=filter_name).exclude(type="hidden")]
        self.assertListEqual(sorted(response_pks), sorted(db_pks))

    def test_filtering_by_categories_success(self):
        response = (self.client.v2 / "rbac" / "roles").get(query={"categories": "cluster_one"})

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["count"], 36)

    def test_list_object_candidates_success(self):
        response = self.client.v2[self.cluster_config_role, "object-candidates"].get()

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(len(response.json()["cluster"]), 2)
        self.assertEqual(response.json()["cluster"][0]["name"], self.cluster_1.name)
        self.assertEqual(response.json()["cluster"][1]["name"], self.cluster_2.name)
