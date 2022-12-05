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

from typing import Any, Callable, Collection, Iterable, TypeVar

import allure
import pytest
from adcm_pytest_plugin.utils import get_data_dir, wait_until_step_succeeds
from tests.ui_tests.app.page.cluster.page import (
    ClusterServicesPage,
    ServiceComponentsPage,
)

# pylint: disable=redefined-outer-name

T = TypeVar("T")
PredicateOfOne = Callable[[T], bool]


@pytest.fixture()
def cluster(sdk_client_fs):
    return sdk_client_fs.upload_from_fs(get_data_dir(__file__)).cluster_create("Awesome")


def attr_is(attribute: str, value: Any) -> PredicateOfOne:
    return lambda object_with_attr: getattr(object_with_attr, attribute) == value


def attr_in(attribute: str, collection: Collection) -> PredicateOfOne:
    return lambda object_with_attr: getattr(object_with_attr, attribute) in collection


def name_is(expected_name: str) -> PredicateOfOne:
    return lambda object_with_name: attr_is("name", expected_name)


def name_in(names: Collection[str]) -> PredicateOfOne:
    return lambda object_with_name: attr_in("name", names)


def get_or_raise(collection: Iterable[T], predicate: Callable[[T], bool]) -> T:
    suitable_object = next(filter(predicate, iter(collection)), None)
    if suitable_object:
        return suitable_object

    raise AssertionError("Failed to get object by given params")


@pytest.mark.usefixtures("_login_to_adcm_over_api")
def test_switch_maintenance_mode(cluster, app_fs, sdk_client_fs, generic_provider):
    no_action_service = cluster.service_add(name="no_mm_action")
    short_action_service = cluster.service_add(name="mm_action")
    long_action_service = cluster.service_add(name="mm_long_action")

    with allure.step("Open page with services and check MM is OFF"):
        services_page = ClusterServicesPage(app_fs.driver, app_fs.adcm.url, cluster_id=cluster.id).open(
            close_popup=True
        )
        services = services_page.get_rows()
        assert len(services) == 3
        assert all(row.maintenance_mode == "OFF" for row in services)

    with allure.step("Turn MM ON on one of services"):
        no_action_row = get_or_raise(services, name_is(no_action_service.name))
        no_action_row.maintenance_mode_button.click()
        wait_until_step_succeeds(lambda: no_action_row.maintenance_mode == "ON", timeout=1, period=0.2)
        wait_until_step_succeeds(
            lambda: (
                get_or_raise(services, name_is(long_action_service.name)).maintenance_mode == "OFF"
                and get_or_raise(services, name_is(short_action_service.name)).maintenance_mode == "OFF"
            ),
            timeout=1,
            period=0.2,
        )

    with allure.step("Check that all service's components are ON, components of another service are OFF"):
        components_page = ServiceComponentsPage(
            app_fs.driver, app_fs.adcm.url, cluster_id=cluster.id, service_id=no_action_service.id
        ).open()
        assert all(row.maintenance_mode == "ON" for row in components_page.get_rows())
        another_components = ServiceComponentsPage(
            app_fs.driver, app_fs.adcm.url, cluster_id=cluster.id, service_id=short_action_service.id
        ).open()
        assert all(row.maintenance_mode == "OFF" for row in another_components.get_rows())

    with allure.step("Change MM back to OFF and check services and components"):
        services_page.open()
        no_action_row = services_page.get_row(name_is(no_action_service.name))
        no_action_row.maintenance_mode_button.click()
        wait_until_step_succeeds(lambda: all(row == "OFF" for row in services_page.get_rows()), timeout=1, period=0.2)
        components_page.open()
        assert all(row.maintenance_mode == "OFF" for row in components_page.get_rows())
