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

"""Test user that has superuser rights"""

# pylint: disable=redefined-outer-name
from functools import partial

import allure
import pytest
from adcm_client.base import NoSuchEndpointOrAccessIsDenied
from adcm_client.objects import ADCMClient, User
from adcm_client.wrappers.api import AccessIsDenied
from adcm_pytest_plugin.utils import catch_failed
from tests.functional.rbac.conftest import BusinessRoles, as_user_objects, is_allowed
from tests.functional.tools import get_object_represent

SUPERUSER_CREDENTIALS = {"username": "supausa", "password": "youcantcrackme"}


_is_allowed_to_superuser = partial(is_allowed, raise_on_superuser=False)


@pytest.fixture()
def superuser(sdk_client_fs: ADCMClient) -> User:
    """Creates user with superuser rights"""
    return sdk_client_fs.user_create(**SUPERUSER_CREDENTIALS, is_superuser=True)


@pytest.fixture()
def superuser_sdk(superuser, adcm_fs) -> ADCMClient:
    """Returns ADCMClient for superuser"""
    creds = SUPERUSER_CREDENTIALS
    return ADCMClient(url=adcm_fs.url, user=creds["username"], password=creds["password"])


def test_access(superuser_sdk, prepare_objects, second_objects):
    """Test that superuser has the same access as Admin"""
    superuser_objects = as_user_objects(superuser_sdk, *prepare_objects)
    superuser_second_objects = as_user_objects(superuser_sdk, *second_objects)

    check_access_to_cluster_objects(superuser_objects, superuser_second_objects)
    check_access_to_provider_objects(superuser_objects)
    check_access_to_general_operations(superuser_sdk, superuser_objects)
    check_access_to_actions_launch(superuser_objects)


@allure.step("Check that superuser has access to cluster-related actions")
def check_access_to_cluster_objects(objects, second_objects):
    """Check that superuser has access to cluster"""
    cluster, service, component, _, host = objects
    second_cluster, second_service, *_ = second_objects

    with allure.step("Check access to basic config manipulations"):
        for obj in cluster, service, component:
            _is_allowed_to_superuser(obj, BusinessRoles.view_config_of(obj))
            _is_allowed_to_superuser(obj, BusinessRoles.edit_config_of(obj))

    with allure.step("Check access to import manipulations"):
        for obj in cluster, service:
            _is_allowed_to_superuser(obj, BusinessRoles.VIEW_IMPORTS)
        _is_allowed_to_superuser(cluster, BusinessRoles.MANAGE_IMPORTS, second_cluster)
        _is_allowed_to_superuser(service, BusinessRoles.MANAGE_IMPORTS, second_service)

    with allure.step("Check access to host-related cluster manipulations"):
        _is_allowed_to_superuser(cluster, BusinessRoles.VIEW_HOST_COMPONENTS)
        _is_allowed_to_superuser(cluster, BusinessRoles.MAP_HOSTS, host)
        _is_allowed_to_superuser(cluster, BusinessRoles.UNMAP_HOSTS, host)
        cluster.host_add(host)
        _is_allowed_to_superuser(cluster, BusinessRoles.EDIT_HOST_COMPONENTS, (host, component))

    with allure.step("Check access to manipulations with services"):
        new_service = _is_allowed_to_superuser(cluster, BusinessRoles.ADD_SERVICE)
        _is_allowed_to_superuser(cluster, BusinessRoles.REMOVE_SERVICE, new_service)

    with allure.step("Check upgrade is available"):
        _is_allowed_to_superuser(cluster, BusinessRoles.UPGRADE_CLUSTER_BUNDLE)


@allure.step("Check that superuser has access to provider-related actions")
def check_access_to_provider_objects(objects):
    """Check that superuser has access to provider"""
    *_, provider, host = objects

    with allure.step("Check access to basic config manipulations"):
        _is_allowed_to_superuser(provider, BusinessRoles.view_config_of(provider))
        _is_allowed_to_superuser(provider, BusinessRoles.edit_config_of(provider))
        _is_allowed_to_superuser(host, BusinessRoles.view_config_of(host))
        _is_allowed_to_superuser(host, BusinessRoles.edit_config_of(host))

    with allure.step("Check access to manipulations with host"):
        new_host = _is_allowed_to_superuser(provider, BusinessRoles.CREATE_HOST)
        _is_allowed_to_superuser(new_host, BusinessRoles.REMOVE_HOSTS)

    with allure.step("Check upgrade is available"):
        _is_allowed_to_superuser(provider, BusinessRoles.UPGRADE_PROVIDER_BUNDLE)


@allure.step("Check that superuser has access to general actions with RBAC and bundles")
def check_access_to_general_operations(client: ADCMClient, objects):  # pylint: disable=too-many-locals
    """Check that superuser has access to RBAC and bundle-related actions"""
    cluster, _, _, provider, _ = objects
    cluster_bundle, provider_bundle = cluster.bundle(), provider.bundle()

    with allure.step("Check access to manipulations with RBAC"):
        for view_role in (
            BusinessRoles.VIEW_USERS,
            BusinessRoles.VIEW_GROUPS,
            BusinessRoles.VIEW_ROLES,
            BusinessRoles.VIEW_POLICIES,
        ):
            _is_allowed_to_superuser(client, view_role)

        for create, edit, remove in (
            (BusinessRoles.CREATE_USER, BusinessRoles.EDIT_USER, BusinessRoles.REMOVE_USER),
            (BusinessRoles.CREATE_GROUP, BusinessRoles.EDIT_GROUP, BusinessRoles.REMOVE_GROUP),
            (BusinessRoles.CREATE_CUSTOM_ROLES, BusinessRoles.EDIT_ROLES, BusinessRoles.REMOVE_ROLES),
        ):
            new_entity = _is_allowed_to_superuser(client, create)
            _is_allowed_to_superuser(new_entity, edit)
            _is_allowed_to_superuser(new_entity, remove)

        new_policy = _is_allowed_to_superuser(
            client,
            BusinessRoles.CREATE_POLICY,
            user=[client.user()],
            role=BusinessRoles.CREATE_CUSTOM_ROLES.value.method_call(client),
        )
        _is_allowed_to_superuser(new_policy, BusinessRoles.EDIT_POLICY)
        _is_allowed_to_superuser(new_policy, BusinessRoles.REMOVE_POLICY)

    with allure.step("Check access to manipulations with cluster, provider and bundles"):
        new_cluster = _is_allowed_to_superuser(cluster_bundle, BusinessRoles.CREATE_CLUSTER)
        _is_allowed_to_superuser(new_cluster, BusinessRoles.REMOVE_CLUSTER)
        new_hostprovider = _is_allowed_to_superuser(provider_bundle, BusinessRoles.CREATE_HOST_PROVIDER)
        _is_allowed_to_superuser(new_hostprovider, BusinessRoles.REMOVE_HOST_PROVIDER)
        new_bundle = _is_allowed_to_superuser(client, BusinessRoles.UPLOAD_BUNDLE)
        _is_allowed_to_superuser(new_bundle, BusinessRoles.REMOVE_BUNDLE)


@allure.step("Check that superuser is allowed to run actions")
def check_access_to_actions_launch(objects):
    """Check that superuser can run actions"""
    for obj in objects:
        with catch_failed(
            (AccessIsDenied, NoSuchEndpointOrAccessIsDenied),
            f"Superuser should has right to run action on {get_object_represent(obj)}",
        ):
            obj.action(name="no_config").run().wait()
