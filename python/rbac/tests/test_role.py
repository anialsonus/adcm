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

import json

from django.test import TestCase
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

from adwp_base.errors import AdwpEx

from cm.models import (
    ProductCategory,
    Action,
    ActionType,
    Cluster,
    ClusterObject,
    ServiceComponent,
    Bundle,
)
from init_db import init as init_adcm
from rbac.models import Role, RoleTypes
from rbac.roles import ModelRole
from rbac.tests.test_base import BaseTestCase
from rbac.upgrade.role import prepare_action_roles, init_roles


class RoleModelTest(TestCase):
    def test_role_class(self):
        r = Role(module_name="qwe")
        with self.assertRaises(AdwpEx) as context:
            r.get_role_obj()
            self.assertEqual(context.exception.error_code, "ROLE_MODULE_ERROR")

        r = Role(module_name="rbac", class_name="qwe")
        with self.assertRaises(AdwpEx) as context:
            r.get_role_obj()
            self.assertEqual(context.exception.error_code, "ROLE_CLASS_ERROR")

        r = Role(module_name="rbac.roles", class_name="ModelRole")
        obj = r.get_role_obj()
        self.assertTrue(isinstance(obj, ModelRole))

    # pylint: disable=protected-access
    def test_max_length(self):
        role = Role.objects.create(name="name", class_name="class", module_name="module")
        name_max_length = role._meta.get_field("name").max_length
        self.assertEqual(name_max_length, 160)
        class_name_max_length = role._meta.get_field("class_name").max_length
        self.assertEqual(class_name_max_length, 32)
        module_name_max_length = role._meta.get_field("module_name").max_length
        self.assertEqual(module_name_max_length, 32)

    def test_default(self):
        role = Role.objects.create()
        self.assertEqual(role.name, "")
        self.assertEqual(role.description, "")
        self.assertFalse(role.child.exists())
        self.assertFalse(role.permissions.exists())
        self.assertEqual(role.module_name, "")
        self.assertEqual(role.class_name, "")
        self.assertEqual(role.init_params, {})
        self.assertTrue(role.built_in)
        self.assertEqual(role.parametrized_by_type, [])


class RoleFunctionalTest(BaseTestCase):
    longMessage = False

    def setUp(self):
        super().setUp()
        init_adcm()
        init_roles()

        category = ProductCategory.objects.create(
            value="Sample Cluster",
            visible=True,
        )
        Bundle.objects.filter(id=self.bundle_1.id).update(
            name="sample_bundle_1",
            version="1.0",
            hash="47b820a6d66a90b02b42017269904ab2c954bceb",
            edition="community",
            license="absent",
            category=category,
        )
        self.bundle_1.refresh_from_db()

        actions = [
            Action(
                name="cluster_action",
                type=ActionType.Job,
                script="./action.yaml",
                script_type="ansible",
                state_available="any",
                prototype=self.clp,
                display_name="Cluster Action",
            ),
            Action(
                name="service_1_action",
                type=ActionType.Job,
                script="./action.yaml",
                script_type="ansible",
                state_available="any",
                prototype=self.sp_1,
                display_name="Service 1 Action",
            ),
            Action(
                name="component_1_1_action",
                type=ActionType.Job,
                script="./action.yaml",
                script_type="ansible",
                state_available="any",
                prototype=self.cop_11,
                display_name="Component 1 from Service 1 Action",
            ),
            Action(
                name="component_2_1_action",
                type=ActionType.Job,
                script="./action.yaml",
                script_type="ansible",
                state_available="any",
                prototype=self.cop_12,
                display_name="Component 2 from Service 1 Action",
            ),
            Action(
                name="service_2_action",
                type=ActionType.Job,
                script="./action.yaml",
                script_type="ansible",
                state_available="any",
                prototype=self.sp_2,
                display_name="Service 2 Action",
            ),
            Action(
                name="component_1_2_action",
                type=ActionType.Job,
                script="./action.yaml",
                script_type="ansible",
                state_available="any",
                prototype=self.cop_21,
                display_name="Component 1 from Service 2 Action",
            ),
            Action(
                name="component_2_2_action",
                type=ActionType.Job,
                script="./action.yaml",
                script_type="ansible",
                state_available="any",
                prototype=self.cop_22,
                display_name="Component 2 from Service 2 Action",
            ),
        ]
        Action.objects.bulk_create(actions)

    def test_cook_roles(self):  # pylint: disable=redefined-outer-name
        prepare_action_roles(self.bundle_1)
        self.check_roles()
        self.check_permission()

    def check_permission(self):
        permissions = [
            {
                "content_type": ContentType.objects.get_for_model(Cluster),
                "codename": "run_action_Cluster Action",
                "name": "Can run Cluster Action actions",
            },
            {
                "content_type": ContentType.objects.get_for_model(ClusterObject),
                "codename": "run_action_Service 1 Action",
                "name": "Can run Service 1 Action actions",
            },
            {
                "content_type": ContentType.objects.get_for_model(ClusterObject),
                "codename": "run_action_Service 2 Action",
                "name": "Can run Service 2 Action actions",
            },
            {
                "content_type": ContentType.objects.get_for_model(ServiceComponent),
                "codename": "run_action_Component 1 from Service 1 Action",
                "name": "Can run Component 1 from Service 1 Action actions",
            },
            {
                "content_type": ContentType.objects.get_for_model(ServiceComponent),
                "codename": "run_action_Component 2 from Service 1 Action",
                "name": "Can run Component 2 from Service 1 Action actions",
            },
            {
                "content_type": ContentType.objects.get_for_model(ServiceComponent),
                "codename": "run_action_Component 1 from Service 2 Action",
                "name": "Can run Component 1 from Service 2 Action actions",
            },
            {
                "content_type": ContentType.objects.get_for_model(ServiceComponent),
                "codename": "run_action_Component 2 from Service 2 Action",
                "name": "Can run Component 2 from Service 2 Action actions",
            },
        ]
        for permission_data in permissions:
            self.assertEqual(
                Permission.objects.filter(**permission_data).count(),
                1,
                f"Permission does not exist:\n{json.dumps(permission_data, default=str, indent=2)}",
            )

    def check_roles(self):
        bundle = self.bundle_1
        roles = make_roles_list(bundle)
        for role_data in roles:
            count = Role.objects.filter(**role_data).count()
            self.assertEqual(
                count,
                1,
                f"Role does not exist or not unique: {count} !=  1\n"
                f"{json.dumps(role_data, indent=2, default=str)}",
            )
            role = Role.objects.filter(**role_data).first()
            if role == RoleTypes.business:
                self.assertEqual(role.child.count(), 1, "Role cannot have more than one child.")
            if role == RoleTypes.hidden:
                self.assertFalse(role.child.exists(), "Role cannot have children.")

        ca_role = Role.objects.get(name="Cluster Administrator")
        self.assertEqual(
            ca_role.child.filter(name="Cluster Action: Cluster Action").count(),
            1,
            "Cluster Action: Cluster Action role missing from base role",
        )
        sa_role = Role.objects.get(name="Service Administrator")
        sa_role_count = sa_role.child.filter(
            name__in=[
                "Service Action: Service 1 Action",
                "Component Action: Component 1 from Service 1 Action",
                "Component Action: Component 2 from Service 1 Action",
                "Service Action: Service 2 Action",
                "Component Action: Component 1 from Service 2 Action",
                "Component Action: Component 2 from Service 2 Action",
            ]
        ).count()
        self.assertEqual(sa_role_count, 6, "Roles missing from base roles")


def make_roles_list(bundle):
    roles = [
        # hidden action roles
        {
            "name": "sample_bundle_1.0_community_cluster_Sample Cluster_cluster_action",
            "display_name": "sample_bundle_1.0_community_cluster_Sample Cluster_cluster_action",
            "bundle": bundle,
            "type": RoleTypes.hidden,
            "module_name": "rbac.roles",
            "class_name": "ActionRole",
            "init_params": {
                "action_id": 3,
                "app_name": "cm",
                "model": "Cluster",
                "filter": {
                    "prototype__name": "sample_cluster",
                    "prototype__type": "cluster",
                    "prototype__bundle_id": bundle.id,
                },
            },
            "parametrized_by_type": ["cluster"],
        },
        {
            "name": "sample_bundle_1.0_community_service_Service 1_service_1_action",
            "display_name": "sample_bundle_1.0_community_service_Service 1_service_1_action",
            "bundle": bundle,
            "type": RoleTypes.hidden,
            "module_name": "rbac.roles",
            "class_name": "ActionRole",
            "init_params": {
                "action_id": 4,
                "app_name": "cm",
                "model": "ClusterObject",
                "filter": {
                    "prototype__name": "service_1",
                    "prototype__type": "service",
                    "prototype__bundle_id": bundle.id,
                },
            },
            "parametrized_by_type": ["service"],
        },
        {
            "name": (
                "sample_bundle_1.0_community_service_service_1_"
                "component_Component 1 from Service 1_component_1_1_action"
            ),
            "display_name": (
                "sample_bundle_1.0_community_service_service_1_"
                "component_Component 1 from Service 1_component_1_1_action"
            ),
            "bundle": bundle,
            "type": RoleTypes.hidden,
            "module_name": "rbac.roles",
            "class_name": "ActionRole",
            "init_params": {
                "action_id": 5,
                "app_name": "cm",
                "model": "ServiceComponent",
                "filter": {
                    "prototype__name": "component_1",
                    "prototype__type": "component",
                    "prototype__bundle_id": bundle.id,
                },
            },
            "parametrized_by_type": ["component"],
        },
        {
            "name": (
                "sample_bundle_1.0_community_service_service_1_"
                "component_Component 2 from Service 1_component_2_1_action"
            ),
            "display_name": (
                "sample_bundle_1.0_community_service_service_1_"
                "component_Component 2 from Service 1_component_2_1_action"
            ),
            "bundle": bundle,
            "type": RoleTypes.hidden,
            "module_name": "rbac.roles",
            "class_name": "ActionRole",
            "init_params": {
                "action_id": 6,
                "app_name": "cm",
                "model": "ServiceComponent",
                "filter": {
                    "prototype__name": "component_2",
                    "prototype__type": "component",
                    "prototype__bundle_id": bundle.id,
                },
            },
            "parametrized_by_type": ["component"],
        },
        {
            "name": "sample_bundle_1.0_community_service_Service 2_service_2_action",
            "display_name": "sample_bundle_1.0_community_service_Service 2_service_2_action",
            "bundle": bundle,
            "type": RoleTypes.hidden,
            "module_name": "rbac.roles",
            "class_name": "ActionRole",
            "init_params": {
                "action_id": 7,
                "app_name": "cm",
                "model": "ClusterObject",
                "filter": {
                    "prototype__name": "service_2",
                    "prototype__type": "service",
                    "prototype__bundle_id": bundle.id,
                },
            },
            "parametrized_by_type": ["service"],
        },
        {
            "name": (
                "sample_bundle_1.0_community_service_service_2_"
                "component_Component 1 from Service 2_component_1_2_action"
            ),
            "display_name": (
                "sample_bundle_1.0_community_service_service_2_"
                "component_Component 1 from Service 2_component_1_2_action"
            ),
            "bundle": bundle,
            "type": RoleTypes.hidden,
            "module_name": "rbac.roles",
            "class_name": "ActionRole",
            "init_params": {
                "action_id": 8,
                "app_name": "cm",
                "model": "ServiceComponent",
                "filter": {
                    "prototype__name": "component_1",
                    "prototype__type": "component",
                    "prototype__bundle_id": bundle.id,
                },
            },
            "parametrized_by_type": ["component"],
        },
        {
            "name": (
                "sample_bundle_1.0_community_service_service_2_"
                "component_Component 2 from Service 2_component_2_2_action"
            ),
            "display_name": (
                "sample_bundle_1.0_community_service_service_2_"
                "component_Component 2 from Service 2_component_2_2_action"
            ),
            "bundle": bundle,
            "type": RoleTypes.hidden,
            "module_name": "rbac.roles",
            "class_name": "ActionRole",
            "init_params": {
                "action_id": 9,
                "app_name": "cm",
                "model": "ServiceComponent",
                "filter": {
                    "prototype__name": "component_2",
                    "prototype__type": "component",
                    "prototype__bundle_id": bundle.id,
                },
            },
            "parametrized_by_type": ["component"],
        },
        # business action roles
        {
            "name": "Cluster Action: Cluster Action",
            "display_name": "Cluster Action: Cluster Action",
            "description": "Cluster Action: Cluster Action",
            "type": RoleTypes.business,
            "module_name": "rbac.roles",
            "class_name": "ParentRole",
            "parametrized_by_type": ["cluster"],
        },
        {
            "name": "Service Action: Service 1 Action",
            "display_name": "Service Action: Service 1 Action",
            "description": "Service Action: Service 1 Action",
            "type": RoleTypes.business,
            "module_name": "rbac.roles",
            "class_name": "ParentRole",
            "parametrized_by_type": ["service"],
        },
        {
            "name": "Component Action: Component 1 from Service 1 Action",
            "display_name": "Component Action: Component 1 from Service 1 Action",
            "description": "Component Action: Component 1 from Service 1 Action",
            "type": RoleTypes.business,
            "module_name": "rbac.roles",
            "class_name": "ParentRole",
            "parametrized_by_type": ["service", "component"],
        },
        {
            "name": "Component Action: Component 2 from Service 1 Action",
            "display_name": "Component Action: Component 2 from Service 1 Action",
            "description": "Component Action: Component 2 from Service 1 Action",
            "type": RoleTypes.business,
            "module_name": "rbac.roles",
            "class_name": "ParentRole",
            "parametrized_by_type": ["service", "component"],
        },
        {
            "name": "Service Action: Service 2 Action",
            "display_name": "Service Action: Service 2 Action",
            "description": "Service Action: Service 2 Action",
            "type": RoleTypes.business,
            "module_name": "rbac.roles",
            "class_name": "ParentRole",
            "parametrized_by_type": ["service"],
        },
        {
            "name": "Component Action: Component 1 from Service 2 Action",
            "display_name": "Component Action: Component 1 from Service 2 Action",
            "description": "Component Action: Component 1 from Service 2 Action",
            "type": RoleTypes.business,
            "module_name": "rbac.roles",
            "class_name": "ParentRole",
            "parametrized_by_type": ["service", "component"],
        },
        {
            "name": "Component Action: Component 2 from Service 2 Action",
            "display_name": "Component Action: Component 2 from Service 2 Action",
            "description": "Component Action: Component 2 from Service 2 Action",
            "type": RoleTypes.business,
            "module_name": "rbac.roles",
            "class_name": "ParentRole",
            "parametrized_by_type": ["service", "component"],
        },
    ]
    return roles
