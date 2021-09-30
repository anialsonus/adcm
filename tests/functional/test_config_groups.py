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
# pylint: disable=redefined-outer-name, unused-argument, duplicate-code, no-self-use

from collections import OrderedDict
from typing import (
    Tuple,
    Union,
    Optional,
)

import allure
import pytest
from adcm_client.objects import (
    ADCMClient,
    Cluster,
    Provider,
    HostList,
    Service,
    Host,
    GroupConfig,
    Component,
    Task,
)
from adcm_pytest_plugin import utils
from adcm_pytest_plugin.steps.actions import (
    run_cluster_action_and_assert_result,
    run_service_action_and_assert_result,
    run_component_action_and_assert_result,
    run_provider_action_and_assert_result,
)
from adcm_pytest_plugin.utils import get_data_dir
from coreapi.exceptions import ErrorMessage

from tests.library.errorcodes import (
    GROUP_CONFIG_HOST_ERROR,
    GROUP_CONFIG_HOST_EXISTS,
)

CLUSTER_BUNDLE_PATH = get_data_dir(__file__, "cluster_simple")
CLUSTER_BUNDLE_WITH_GROUP_PATH = get_data_dir(__file__, "cluster_with_group_all_params")
PROVIDER_BUNDLE_PATH = get_data_dir(__file__, "hostprovider_bundle")
PROVIDER_BUNDLE_WITH_GROUP_PATH = get_data_dir(__file__, "provider_group_with_all_params")
HOST_ERROR_MESSAGE = (
    "host is not available for this object, or host already is a member of another group of this object"
)
HOST_EXISTS_MESSAGE = "the host is already a member of this group"
FIRST_COMPONENT_NAME = "first"
SECOND_COMPONENT_NAME = "second"
FIRST_GROUP = "test_group"
SECOND_GROUP = "test_group_2"
FIRST_HOST = "test_host_1"
SECOND_HOST = "test_host_2"


@pytest.fixture()
def provider_bundle(request, sdk_client_fs: ADCMClient):
    bundle_path = request.param if hasattr(request, "param") else PROVIDER_BUNDLE_PATH
    return sdk_client_fs.upload_from_fs(bundle_path)


@pytest.fixture()
def cluster_bundle(request, sdk_client_fs: ADCMClient):
    bundle_path = request.param if hasattr(request, "param") else CLUSTER_BUNDLE_PATH
    return sdk_client_fs.upload_from_fs(bundle_path)


@pytest.fixture()
def cluster(cluster_bundle) -> Cluster:
    return cluster_bundle.cluster_create(name=utils.random_string())


@pytest.fixture()
def provider(provider_bundle) -> Provider:
    return provider_bundle.provider_create(name=utils.random_string())


@pytest.fixture()
def create_two_hosts(provider) -> Tuple[Host, Host]:
    with allure.step("Create host for config groups"):
        test_host_1 = provider.host_create(fqdn=FIRST_HOST)
    with allure.step("Create host for host candidate check"):
        test_host_2 = provider.host_create(fqdn=SECOND_HOST)
    return test_host_1, test_host_2


@pytest.fixture()
def cluster_with_two_hosts_on_it(create_two_hosts, cluster: Cluster, provider: Provider) -> Tuple[Host, Host, Cluster]:
    """Add service, two hosts and create components to check intersection in config groups"""

    test_host_1, test_host_2 = create_two_hosts
    cluster.host_add(test_host_1)
    cluster.host_add(test_host_2)
    return test_host_1, test_host_2, cluster


@pytest.fixture()
def cluster_with_components(cluster_with_two_hosts_on_it) -> Tuple[Service, Host, Host]:
    """Add service, two hosts and create components to check intersection in config groups"""

    test_host_1, test_host_2, cluster = cluster_with_two_hosts_on_it
    service = cluster.service_add(name='test_service_1')
    cluster.hostcomponent_set(
        (test_host_1, service.component(name=FIRST_COMPONENT_NAME)),
        (test_host_2, service.component(name=FIRST_COMPONENT_NAME)),
        (test_host_2, service.component(name=SECOND_COMPONENT_NAME)),
    )
    return service, test_host_1, test_host_2


@pytest.fixture()
def cluster_with_components_on_first_host(
    create_two_hosts, cluster: Cluster, provider: Provider
) -> Tuple[Service, Host, Host]:
    """Add service, two hosts and create components to check config groups"""

    service = cluster.service_add(name='test_service_1')
    test_host_1, test_host_2 = create_two_hosts
    cluster.host_add(test_host_1)
    cluster.hostcomponent_set(
        (test_host_1, service.component(name=FIRST_COMPONENT_NAME)),
        (test_host_1, service.component(name=SECOND_COMPONENT_NAME)),
    )
    return service, test_host_1, test_host_2


@allure.step('Check error')
def assert_that_host_add_is_unavailable(service_group: GroupConfig, host: Host):
    with allure.step(f'Check that error is "{GROUP_CONFIG_HOST_ERROR.code}"'):
        with pytest.raises(ErrorMessage) as e:
            service_group.host_add(host)
        GROUP_CONFIG_HOST_ERROR.equal(e)
    with allure.step(f'Check error message is "{HOST_ERROR_MESSAGE}"'):
        assert HOST_ERROR_MESSAGE in e.value.error['desc'], f"Should be error message '{HOST_ERROR_MESSAGE}'"


@allure.step('Check that host exists')
def assert_that_host_exists(group: GroupConfig, host: Host):
    with allure.step(f'Check that error is "{GROUP_CONFIG_HOST_EXISTS.code}"'):
        with pytest.raises(ErrorMessage) as e:
            group.host_add(host)
        GROUP_CONFIG_HOST_EXISTS.equal(e)
    with allure.step(f'Check error message is "{HOST_EXISTS_MESSAGE}"'):
        assert HOST_EXISTS_MESSAGE in e.value.error['desc'], f"Should be error message '{HOST_EXISTS_MESSAGE}'"


@allure.step('Check that host is in the group')
def assert_host_is_in_group(group: GroupConfig, host: Host):
    assert host.fqdn in [h.fqdn for h in group.hosts().data], f'Host "{host.fqdn}" should be in group "{group.name}"'


@allure.step("Check that the only second host is present in candidates on second group")
def assert_host_candidate_equal_expected(group: HostList, expected_hosts_names: [str]):
    expected_hosts_amount = len(expected_hosts_names)
    with allure.step(f"Check that {expected_hosts_amount} hosts are available in group"):
        assert len(group) == expected_hosts_amount, f"{expected_hosts_amount} hosts should be available in group"
    with allure.step(f"Check that host '{SECOND_HOST}' is available in group"):
        assert [g.fqdn for g in group] == expected_hosts_names, f"Should be available hosts '{expected_hosts_names}'"


@allure.step("Create config group and add host")
def _create_group_and_add_host(
    object_with_group: Union[Cluster, Service, Component, Provider], host: Host
) -> GroupConfig:
    group = object_with_group.group_config_create(name=FIRST_GROUP)
    group.host_add(host)
    return group


class TestGroupsIntersection:
    def test_that_groups_not_allowed_to_intersect_in_cluster(self, sdk_client_fs, cluster_with_two_hosts_on_it):
        """Test that groups are not allowed to intersect in cluster"""

        test_host_1, test_host_2, cluster = cluster_with_two_hosts_on_it
        _create_group_and_add_host(cluster, test_host_1)
        with allure.step("Create the second group for cluster and check that not allowed to add the first host to it"):
            cluster_group_2 = cluster.group_config_create(name=SECOND_GROUP)
            assert_that_host_add_is_unavailable(cluster_group_2, test_host_1)
            assert_host_candidate_equal_expected(cluster_group_2.host_candidate(), [SECOND_HOST])

    def test_that_groups_not_allowed_to_intersect_in_provider(self, sdk_client_fs, create_two_hosts, provider):
        """Test that groups are not allowed to intersect in provider"""

        test_host_1, _ = create_two_hosts
        _create_group_and_add_host(provider, test_host_1)
        with allure.step("Create the second group for provider and check that not allowed to add the first host to it"):
            provider_group_2 = provider.group_config_create(name=SECOND_GROUP)
            assert_that_host_add_is_unavailable(provider_group_2, test_host_1)
            assert_host_candidate_equal_expected(provider_group_2.host_candidate(), [SECOND_HOST])

    def test_that_groups_not_allowed_to_intersect_in_service(self, sdk_client_fs, cluster, cluster_with_components):
        """Test that groups are not allowed to intersect in service"""

        service, test_host_1, _ = cluster_with_components
        _create_group_and_add_host(service, test_host_1)
        with allure.step("Create the second group for service and check that not allowed to add the first host to it"):
            service_group_2 = service.group_config_create(name=SECOND_GROUP)
            assert_that_host_add_is_unavailable(service_group_2, test_host_1)
            assert_host_candidate_equal_expected(service_group_2.host_candidate(), [SECOND_HOST])

    def test_that_groups_not_allowed_to_intersect_in_component(self, sdk_client_fs, cluster_with_components):
        """Test that groups are not allowed to intersect"""

        service, test_host_1, _ = cluster_with_components
        _create_group_and_add_host(service.component(name=FIRST_COMPONENT_NAME), test_host_1)
        with allure.step(
            "Create the second group for component and check that not allowed to add the first host to it"
        ):
            component_group_2 = service.component(name=FIRST_COMPONENT_NAME).group_config_create(name=SECOND_GROUP)
        assert_that_host_add_is_unavailable(component_group_2, test_host_1)
        assert_host_candidate_equal_expected(component_group_2.host_candidate(), [SECOND_HOST])


class TestIncorrectHostInGroups:
    """Test for incorrect hosts in group caused errors like GROUP_CONFIG_HOST_ERROR or GROUP_CONFIG_HOST_EXISTS"""

    def test_add_incorrect_host_to_provider_group(self, sdk_client_fs, provider_bundle, provider):
        """Test exception rise when we try to add incorrect host to provider group"""
        with allure.step("Create host from first provider"):
            correct_host = provider.host_create(fqdn=utils.random_string())
        with allure.step("Create second provider"):
            provider_2 = provider_bundle.provider_create(name="Second test provider")
        with allure.step("Create host from second provider"):
            incorrect_host = provider_2.host_create(fqdn=utils.random_string())
        with allure.step("Create config group for first provider and try to add the first host"):
            provider_group = provider.group_config_create(name=incorrect_host.fqdn)
            assert_that_host_add_is_unavailable(provider_group, incorrect_host)
            assert_host_candidate_equal_expected(provider_group.host_candidate(), [correct_host.fqdn])
        with allure.step("Add first host to provider group and check that second add is not available"):
            provider_group.host_add(correct_host)
            assert_that_host_exists(provider_group, correct_host)
            assert_host_candidate_equal_expected(provider_group.host_candidate(), [])

    def test_add_incorrect_host_to_service_group(self, cluster_with_components_on_first_host):
        """Test exception rise when we try to add incorrect host to service group"""

        service, test_host_1, test_host_2 = cluster_with_components_on_first_host
        with allure.step("Create group for service"):
            service_group = service.group_config_create(name=FIRST_GROUP)
        with allure.step("Try to add the second host not from service and check group hosts list"):
            assert_that_host_add_is_unavailable(service_group, test_host_2)
            assert_host_candidate_equal_expected(service_group.host_candidate(), [FIRST_HOST])
        with allure.step("Add first host to service group and check that second add is not available"):
            service_group.host_add(test_host_1)
            assert_that_host_exists(service_group, test_host_1)
            assert_host_candidate_equal_expected(service_group.host_candidate(), [])

    def test_add_incorrect_host_to_cluster_group(self, cluster_bundle, cluster, create_two_hosts):
        """Test exception rise when we try to add incorrect host to cluster group"""

        test_host_1, test_host_2 = create_two_hosts
        with allure.step("Create second cluster"):
            cluster_2 = cluster_bundle.cluster_create(name=utils.random_string())
        with allure.step("Add hosts to clusters"):
            cluster.host_add(test_host_1)
            cluster_2.host_add(test_host_2)
        with allure.step("Create group for first cluster"):
            cluster_group = cluster.group_config_create(name=FIRST_GROUP)
        with allure.step("Try to add host from second cluster to first cluster group"):
            assert_that_host_add_is_unavailable(cluster_group, test_host_2)
            assert_host_candidate_equal_expected(cluster_group.host_candidate(), [FIRST_HOST])
        with allure.step("Add first host to cluster group and check that second add is not available"):
            cluster_group.host_add(test_host_1)
            assert_that_host_exists(cluster_group, test_host_1)
            assert_host_candidate_equal_expected(cluster_group.host_candidate(), [])

    def test_add_incorrect_host_to_component_group(self, cluster_with_components_on_first_host):
        """Test exception rise when we try to add incorrect host to component group"""

        service, test_host_1, test_host_2 = cluster_with_components_on_first_host
        with allure.step("Create group for component"):
            component_group = service.component(name=FIRST_COMPONENT_NAME).group_config_create(name=FIRST_GROUP)
        with allure.step("Try to add host not from cluster to component group"):
            assert_that_host_add_is_unavailable(component_group, test_host_2)
            assert_host_candidate_equal_expected(component_group.host_candidate(), [FIRST_HOST])
        with allure.step("Add first host to component group and check that second add is not available"):
            component_group.host_add(test_host_1)
            assert_that_host_exists(component_group, test_host_1)
            assert_host_candidate_equal_expected(component_group.host_candidate(), [])


class TestDeleteHostInGroups:
    """Test deleting host related to conf group"""

    @allure.step("Check that there are no hosts in conf group")
    def check_no_hosts_in_group(self, group: GroupConfig):
        assert len(group.hosts()) == 0, "Should not be any hosts in conf group"

    def test_delete_host_from_group_after_deleting_in_cluster(self, sdk_client_fs, cluster, provider):
        """Test that host removed from conf group after removing from cluster"""

        test_host = provider.host_create(fqdn=FIRST_HOST)
        cluster.host_add(test_host)
        cluster_group = _create_group_and_add_host(cluster, test_host)
        assert_host_is_in_group(cluster_group, test_host)
        cluster.host_delete(test_host)
        self.check_no_hosts_in_group(cluster_group)
        with allure.step("Check that there are no hosts available to add in cluster group"):
            assert_host_candidate_equal_expected(cluster_group.host_candidate(), [])

    def test_delete_host_from_group_after_deleting_in_service(
        self, cluster, sdk_client_fs, cluster_with_components_on_first_host
    ):
        """Test that host removed from conf group after removing from service"""

        service, test_host_1, test_host_2 = cluster_with_components_on_first_host
        service_group = _create_group_and_add_host(service, test_host_1)
        assert_host_is_in_group(service_group, test_host_1)
        with allure.step("Change host in service"):
            cluster.host_add(test_host_2)
            cluster.hostcomponent_set(
                (test_host_2, service.component(name=FIRST_COMPONENT_NAME)),
                (test_host_2, service.component(name=SECOND_COMPONENT_NAME)),
            )
        self.check_no_hosts_in_group(service_group)

    def test_delete_host_from_group_after_delete_in_component(
        self, cluster, sdk_client_fs, cluster_with_components_on_first_host
    ):
        """Test that host removed from conf group after removing from component"""

        service, test_host_1, test_host_2 = cluster_with_components_on_first_host
        component_group = _create_group_and_add_host(service.component(name=FIRST_COMPONENT_NAME), test_host_1)
        assert_host_is_in_group(component_group, test_host_1)
        with allure.step("Change host in component"):
            cluster.host_add(test_host_2)
            cluster.hostcomponent_set(
                (test_host_2, service.component(name=FIRST_COMPONENT_NAME)),
                (test_host_2, service.component(name=SECOND_COMPONENT_NAME)),
            )
        self.check_no_hosts_in_group(component_group)

    def test_delete_host_from_group_after_it_deleted(self, sdk_client_fs, provider):
        """Test that host removed from provider conf group after deleting"""

        test_host = provider.host_create(fqdn=FIRST_HOST)
        provider_group = _create_group_and_add_host(provider, test_host)
        assert_host_is_in_group(provider_group, test_host)
        with allure.step("Delete host"):
            test_host.delete()
        self.check_no_hosts_in_group(provider_group)


class TestChangeGroupsConfig:
    """Tests for changing group config"""

    ASSERT_TYPE = ["float", "boolean", "integer", "string", "list", "option", "text", "group", "structure", "map"]

    PARAMS_TO_CHANGE = [
        1.1,
        False,
        0,
        "string2",
        ["/dev/rdisk0s4", "/dev/rdisk0s5", "/dev/rdisk0s6"],
        "WEEKLY",
        "testtext",
        {"readonly-key": "value", "writable-key": "value test 2", "required": 0},
        [{"code": 3, "country": "Test1"}, {"code": 4, "country": "Test2"}],
        {"age": "20", "name": "Chloe", "sex": "f"},
        "123",
        "file content test",
    ]

    def add_values_to_group_config_template(self, params: list = PARAMS_TO_CHANGE) -> dict:
        (
            float_value,
            boolean_value,
            integer_value,
            string_value,
            list_value,
            option,
            text,
            group,
            structure,
            map,
            password,
            file,
        ) = params
        return {
            "attr": {
                "group": {"active": True},
                "group_keys": {
                    "group": {"readonly-key": True, "writable-key": True, "required": True},
                    "float": True,
                    "boolean": True,
                    "integer": True,
                    "password": True,
                    "string": True,
                    "list": True,
                    "file": True,
                    "option": True,
                    "text": True,
                    "structure": True,
                    "map": True,
                },
            },
            "config": {
                "float": float_value,
                "boolean": boolean_value,
                "integer": integer_value,
                "password": password,
                "string": string_value,
                "list": list_value,
                "file": file,
                "option": option,
                "text": text,
                "group": group,
                "structure": structure,
                "map": map,
            },
        }

    @allure.step("Check group config values are equal expected")
    def _check_values_in_group(
        self, values_after: Union[OrderedDict, dict], expected_values: dict, values_before: Optional[OrderedDict] = None
    ):
        """Checks that params in config group are equal to expected and password has been changed"""

        for item in self.ASSERT_TYPE:
            assert (
                values_after[item] == expected_values[item]
            ), f'Value is "{values_after[item]}", but should be {expected_values[item]}'
        if values_before:
            assert values_after["password"] != values_before["password"], "Password has not changed"
        if values_after["file"]:
            assert values_after["file"] == expected_values["file"], "File has not changed"

    @allure.step("Get group config values from logs in task")
    def _get_host_config_from_log(self, log, host_name) -> dict:
        """Create dict with group config values from logs in task"""

        config_string = log.split(f"[{host_name}]")[1].split("msg: \'")[1].split("\n")[0]
        config_list = config_string.replace("''", "'").split(";")
        config_list[0] = float(config_list[0])
        config_list[1] = bool(config_list[1] is True or config_list[1] == "True")
        config_list[2] = int(config_list[2])
        config_list[4] = (
            config_list[4]
            if isinstance(config_list[4], list)
            else config_list[4].replace(" ", "").replace("'", "").replace("]", "").replace("[", "").split(",")
        )
        config_list[7] = eval(config_list[7])
        config_list[8] = [
            {
                "code": int(config_list[8].split("code':")[1].split(',')[0]),
                "country": config_list[8].split("country': '")[1].split("'}")[0],
            },
            {
                "code": int(config_list[8].split("code':")[2].split(',')[0]),
                "country": config_list[8].split("country': '")[2].split("'}")[0],
            },
        ]
        config_list[9] = eval(config_list[9][:-1])
        config_list.append(None)
        config_list.append(None)
        return self.add_values_to_group_config_template(config_list)

    def check_group_config_from_action_log(
        self,
        task: Task,
        test_host_1: Host,
        test_host_2: Host,
        config_expected: dict,
        config_before: Optional[OrderedDict] = None,
    ):
        with allure.step("Check that first host config has been changed"):
            test_host_1_task_log = self._get_host_config_from_log(
                log=task.job().log_list().data[0].content, host_name=test_host_1.fqdn
            )
            self._check_values_in_group(test_host_1_task_log['config'], config_expected['config'], config_before)
        with allure.step("Check that second host config has not been changed"):
            test_host_2_task_log = self._get_host_config_from_log(
                log=task.job().log_list().data[0].content, host_name=test_host_2.fqdn
            )
            self._check_values_in_group(values_after=test_host_2_task_log['config'], expected_values=config_before)

    @pytest.mark.parametrize(
        "cluster_bundle",
        [pytest.param(get_data_dir(__file__, CLUSTER_BUNDLE_WITH_GROUP_PATH), id="cluster_with_group")],
        indirect=True,
    )
    def test_change_group_in_cluster(self, cluster_bundle, cluster_with_two_hosts_on_it):
        """Test that groups in cluster are allowed change with group_customization: true"""

        test_host_1, test_host_2, cluster = cluster_with_two_hosts_on_it
        with allure.step("Create config group for cluster and add first host"):
            cluster_group = _create_group_and_add_host(cluster, test_host_1)
            config_before = cluster_group.config()
        config_expected = self.add_values_to_group_config_template()
        config_after = cluster_group.config_set_diff(config_expected)
        self._check_values_in_group(
            values_after=config_after['config'], expected_values=config_expected['config'], values_before=config_before
        )
        task = run_cluster_action_and_assert_result(cluster, action="test_action")
        self.check_group_config_from_action_log(task, test_host_1, test_host_2, config_expected, config_before)

    @pytest.mark.parametrize(
        "cluster_bundle",
        [pytest.param(get_data_dir(__file__, CLUSTER_BUNDLE_WITH_GROUP_PATH), id="cluster_with_group")],
        indirect=True,
    )
    def test_change_group_in_service(self, cluster_bundle, sdk_client_fs, cluster_with_components):
        """Test that groups in service are allowed change with group_customization: true"""

        service, test_host_1, test_host_2 = cluster_with_components
        with allure.step("Create config group for service and add first host"):
            service_group = _create_group_and_add_host(service, test_host_1)
            config_before = service_group.config()
        config_expected = self.add_values_to_group_config_template()
        config_after = service_group.config_set_diff(config_expected)
        self._check_values_in_group(
            values_after=config_after['config'], expected_values=config_expected['config'], values_before=config_before
        )
        task = run_service_action_and_assert_result(service, action="test_action")
        self.check_group_config_from_action_log(task, test_host_1, test_host_2, config_expected, config_before)

    @pytest.mark.parametrize(
        "cluster_bundle",
        [pytest.param(get_data_dir(__file__, CLUSTER_BUNDLE_WITH_GROUP_PATH), id="cluster_with_group")],
        indirect=True,
    )
    def test_change_group_in_component(self, cluster_bundle, sdk_client_fs, cluster_with_components):
        """Test that groups in component are allowed change with group_customization: true"""

        service, test_host_1, test_host_2 = cluster_with_components
        component = service.component(name=FIRST_COMPONENT_NAME)
        with allure.step("Create config group for components and add first host"):
            component_group = _create_group_and_add_host(component, test_host_1)
            config_before = component_group.config()
        config_expected = self.add_values_to_group_config_template()
        config_after = component_group.config_set_diff(config_expected)
        self._check_values_in_group(
            values_after=config_after['config'], expected_values=config_expected['config'], values_before=config_before
        )
        task = run_component_action_and_assert_result(component, action="test_action")
        self.check_group_config_from_action_log(task, test_host_1, test_host_2, config_expected, config_before)

    @pytest.mark.parametrize(
        "provider_bundle",
        [pytest.param(get_data_dir(__file__, PROVIDER_BUNDLE_WITH_GROUP_PATH), id="provider_with_group")],
        indirect=True,
    )
    def test_change_group_in_provider(self, sdk_client_fs, provider_bundle, provider, create_two_hosts):
        """Test that groups in provider are allowed change with group_customization: true"""

        test_host_1, test_host_2 = create_two_hosts
        with allure.step("Create config group for provider and add first host"):
            provider_group = _create_group_and_add_host(provider, test_host_1)
            config_before = provider_group.config()
        config_expected = self.add_values_to_group_config_template()
        config_after = provider_group.config_set_diff(config_expected)
        self._check_values_in_group(
            values_after=config_after['config'], expected_values=config_expected['config'], values_before=config_before
        )
        task = run_provider_action_and_assert_result(provider, action="test_action")
        self.check_group_config_from_action_log(task, test_host_1, test_host_2, config_expected, config_before)
