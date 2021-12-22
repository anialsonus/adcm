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
"""Common fixtures and steps for rbac testing"""
import os
from enum import Enum
from operator import methodcaller
from typing import Callable, NamedTuple, Union, List

import allure
import pytest
from adcm_client.base import NoSuchEndpointOrAccessIsDenied, BaseAPIObject
from adcm_client.objects import ADCMClient, User, Group
from adcm_client.wrappers.api import AccessIsDenied
from adcm_pytest_plugin.utils import catch_failed, random_string

# pylint: disable=redefined-outer-name,unused-argument

# Enum names doesn't conform to UPPER_CASE naming style
# pylint: disable=invalid-name

TEST_USER_CREDENTIALS = "test_user", "password"
DATA_DIR = os.path.join(os.path.dirname(__file__), "test_business_permissions_data")


class RbacRoles(Enum):
    """
    Pre-defined rbac user roles
    """

    ADCMUser = "ADCM User"
    ServiceAdministrator = "Service Administrator"
    ClusterAdministrator = "Cluster Administrator"
    ADCMAdministrator = "ADCM Administrator"


class BusinessRole(NamedTuple):
    """Mapping for business role and func to check role permissions"""

    role_name: str
    method_call: Callable


class BusinessRoles(Enum):
    """Complete list of business roles"""

    # pylint: disable=invalid-name

    ViewConfigurations = BusinessRole("View configurations", methodcaller("config"))
    EditConfigurations = BusinessRole("Edit configurations", methodcaller("config_set_diff", {}))
    ViewImports = BusinessRole("View imports", methodcaller("imports"))
    ManageImports = BusinessRole("Manage imports", lambda x, *args: x.bind(*args))
    ViewHostComponents = BusinessRole("View Host-Components", methodcaller("hostcomponent"))
    EditHostComponents = BusinessRole("Edit Host-Components", lambda x, *args: x.hostcomponent_set(*args))
    AddService = BusinessRole("Add service", methodcaller("service_add", name="new_service"))
    RemoveService = BusinessRole("Remove service", lambda x, *args: x.service_delete(*args))
    RemoveHosts = BusinessRole("Remove hosts", methodcaller("delete"))
    MapHosts = BusinessRole("Map hosts", lambda x, *args: x.host_add(*args))
    UnmapHosts = BusinessRole("Unmap hosts", lambda x, *args: x.host_delete(*args))
    UpgradeBundle = BusinessRole("Upgrade bundle", lambda x: x.upgrade().do())
    CreateHostProvider = BusinessRole(
        "Create provider", methodcaller("provider_create", name=f"new_provider {random_string(5)}")
    )
    CreateHost = BusinessRole("Create host", methodcaller("host_create", fqdn=f"new_host_{random_string(5)}"))
    RemoveHostProvider = BusinessRole("Remove provider", methodcaller("delete"))
    CreateCluster = BusinessRole(
        "Create cluster", methodcaller("cluster_create", name=f"new_cluster {random_string(5)}")
    )
    RemoveCluster = BusinessRole("Remove cluster", methodcaller("delete"))
    UploadBundle = BusinessRole("Upload bundle", methodcaller("upload_from_fs", os.path.join(DATA_DIR, "dummy")))
    RemoveBundle = BusinessRole("Remove bundle", methodcaller("delete"))
    ViewADCMSettings = BusinessRole("View ADCM settings", methodcaller("config"))
    EditADCMSettings = BusinessRole("Edit ADCM settings", methodcaller("config_set_diff", {}))
    ViewUsers = BusinessRole("View users", methodcaller("user_list"))
    CreateUser = BusinessRole("Create user", methodcaller("user_create", username="test", password="test"))
    RemoveUser = BusinessRole("Remove user", methodcaller("delete"))
    EditUser = BusinessRole("Edit user", methodcaller("update", first_name=random_string(5)))
    ViewRoles = BusinessRole("View roles", methodcaller("role_list"))
    CreateCustomRoles = BusinessRole(
        "Create custom role",
        methodcaller(
            "role_create", name="Custom role", display_name="Custom role", parametrized_by=[], child=[{"id": 1}]
        ),
    )
    RemoveRoles = BusinessRole("Remove roles", methodcaller("delete"))
    EditRoles = BusinessRole("Edit role", methodcaller("update", display_name=random_string(5)))
    ViewGroups = BusinessRole("View group", methodcaller("group_list"))
    CreateGroup = BusinessRole("Create group", methodcaller("group_create", name="test"))
    RemoveGroup = BusinessRole("Remove group", methodcaller("delete"))
    EditGroup = BusinessRole("Edit group", methodcaller("update", name=random_string(5)))
    ViewPolicies = BusinessRole("View policy", methodcaller("policy_list"))
    CreatePolicy = BusinessRole(
        "Create policy", lambda x, **kwargs: x.policy_create(name="Test policy", objects=[], **kwargs)
    )
    RemovePolicy = BusinessRole("Remove policy", methodcaller("delete"))
    EditPolicy = BusinessRole("Edit policy", methodcaller("update", name=random_string(5)))


@pytest.fixture()
@allure.title("Create test user")
def user(sdk_client_fs) -> User:
    """Create user for testing"""
    return sdk_client_fs.user_create(*TEST_USER_CREDENTIALS)


@pytest.fixture()
def user_sdk(user, adcm_fs) -> ADCMClient:
    """Returns ADCMClient object from adcm_client with testing user"""
    username, password = TEST_USER_CREDENTIALS
    return ADCMClient(url=adcm_fs.url, user=username, password=password)


@pytest.fixture()
def user_policy(request, user, sdk_client_fs, prepare_objects):
    """
    Create testing role and policy
    Parametrize this fixture with `use_role` decorator
    """
    return create_policy(sdk_client_fs, request.param, objects=prepare_objects, users=[user], groups=[])


def use_role(role: BusinessRoles):
    """Decorate test func to prepare test user with required business role"""
    return pytest.mark.parametrize("user_policy", [role], indirect=True)


@pytest.fixture()
def prepare_objects(sdk_client_fs, user_sdk):
    """
    Prepare adcm objects
    Created objects should be used as a `parametrized_by_type` values on policy with tested role
    """
    cluster_bundle = sdk_client_fs.upload_from_fs(os.path.join(DATA_DIR, "cluster"))
    cluster = cluster_bundle.cluster_create("Cluster")
    service = cluster.service_add(name="test_service")
    component = service.component()
    provider_bundle = sdk_client_fs.upload_from_fs(os.path.join(DATA_DIR, "provider"))
    provider = provider_bundle.provider_create("Provider")
    host = provider.host_create("Host")
    return cluster, service, component, provider, host


@pytest.fixture()
def second_objects(sdk_client_fs, user_sdk):
    """
    Prepare second adcm objects
    Its objects should not be allowed on tested user
    """
    cluster_bundle = sdk_client_fs.upload_from_fs(os.path.join(DATA_DIR, "second_cluster"))
    cluster = cluster_bundle.cluster_create("Second Cluster")
    service = cluster.service_add(name="test_service")
    component = service.component()
    provider_bundle = sdk_client_fs.upload_from_fs(os.path.join(DATA_DIR, "second_provider"))
    provider = provider_bundle.provider_create("Second Provider")
    host = provider.host_create("Second_Host")
    return cluster, service, component, provider, host


def as_user_objects(user_sdk: ADCMClient, base_objects):
    """Get prepared objects via tested user sdk"""
    cluster, service, component, provider, host = base_objects
    return (
        user_sdk.cluster(id=cluster.id),
        user_sdk.service(id=service.id),
        user_sdk.component(id=component.id),
        user_sdk.provider(id=provider.id),
        user_sdk.host(id=host.id),
    )


@allure.step("Delete policy")
def delete_policy(policy):
    """Delete policy"""
    policy.delete()


def create_policy(sdk_client, permission: BusinessRoles, objects: list, users: List[User], groups: List[Group]):
    """Create a new policy for the user and role"""
    role_name = permission.value.role_name

    business_role = sdk_client.role(name=role_name)
    role = sdk_client.role_create(
        name=f"Testing {role_name} {random_string(5)}",
        display_name=f"Testing {role_name}",
        parametrized_by=["cluster", "service", "component", "host", "provider"],
        child=[{"id": business_role.id}],
    )
    policy = sdk_client.policy_create(
        name=f"Policy with role {role_name}", role=role, objects=objects, user=users, group=groups
    )
    return policy


def is_allowed(base_object: Union[BaseAPIObject, ADCMClient], business_role: BusinessRoles, *args, **kwargs):
    """
    Assert that role is allowed on object
    """
    with allure.step(
        f"Assert that {business_role.value.role_name} on {base_object.__class__.__name__} is allowed"
    ), catch_failed(
        (AccessIsDenied, NoSuchEndpointOrAccessIsDenied),
        f"{business_role.value.role_name} on {base_object.__class__.__name__} should be allowed",
    ):
        business_role.value.method_call(base_object, *args, **kwargs)


def is_denied(base_object: Union[BaseAPIObject, ADCMClient], business_role: BusinessRoles, *args, **kwargs):
    """
    Assert that role is denied on object
    """
    with allure.step(f"Assert that {business_role.value.role_name} on {base_object.__class__.__name__} is denied"):
        try:
            business_role.value.method_call(base_object, *args, **kwargs)
        except (AccessIsDenied, NoSuchEndpointOrAccessIsDenied):
            pass
        else:
            raise AssertionError(
                f"{business_role.value.role_name} on {base_object.__class__.__name__} should not be allowed"
            )
