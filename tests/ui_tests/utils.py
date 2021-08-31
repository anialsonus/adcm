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

# pylint: disable=too-many-ancestors
from collections import UserDict
from contextlib import contextmanager
from typing import Callable, TypeVar, Any, Union, Optional, Dict, Tuple, Sized

import allure
import requests

from adcm_client.objects import ADCMClient, Cluster
from adcm_pytest_plugin.utils import random_string, wait_until_step_succeeds
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait as WDW

from tests.ui_tests.app.app import ADCMTest
from tests.ui_tests.app.configuration import Configuration

ValueType = TypeVar('ValueType')
FuncType = TypeVar('FuncType')


def prepare_cluster(sdk_client: ADCMClient, path) -> Cluster:
    bundle = sdk_client.upload_from_fs(path)
    cluster_name = "_".join(path.split("/")[-1:] + [random_string()])
    cluster = bundle.cluster_create(name=cluster_name)
    return cluster


@allure.step("Prepare cluster and get config")
def prepare_cluster_and_get_config(sdk_client: ADCMClient, path, app):
    cluster = prepare_cluster(sdk_client, path)
    config = Configuration(app.driver, f"{app.adcm.url}/cluster/{cluster.cluster_id}/config")
    return cluster, config


class BundleObjectDefinition(UserDict):
    def __init__(self, obj_type=None, name=None, version=None):
        super().__init__()
        self["type"] = obj_type
        self["name"] = name
        if version is not None:
            self["version"] = version

    def _set_ui_option(self, option, value):
        if "ui_options" not in self:
            self["ui_options"] = {}
        self["ui_options"][option] = value

    def set_advanced(self, value):
        self._set_ui_option("advanced", value)

    @classmethod
    def to_dict(cls, obj) -> dict:
        if isinstance(obj, cls):
            obj = cls.to_dict(obj.data)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                obj[i] = cls.to_dict(v)
        elif isinstance(obj, dict):
            for k in obj:
                obj[k] = cls.to_dict(obj[k])
        return obj


class ClusterDefinition(BundleObjectDefinition):
    def __init__(self, name=None, version=None):
        super().__init__(obj_type="cluster", name=name, version=version)


class ServiceDefinition(BundleObjectDefinition):
    def __init__(self, name=None, version=None):
        super().__init__(obj_type="service", name=name, version=version)


class ProviderDefinition(BundleObjectDefinition):
    def __init__(self, name=None, version=None):
        super().__init__(obj_type="provider", name=name, version=version)


class HostDefinition(BundleObjectDefinition):
    def __init__(self, name=None, version=None):
        super().__init__(obj_type="host", name=name, version=version)


class GroupDefinition(BundleObjectDefinition):
    def __init__(self, name=None):
        super().__init__(obj_type="group", name=name)
        self["activatable"] = True
        self["subs"] = []

    def add_fields(self, *fields):
        for field in fields:
            self["subs"].append(field)
        return self


class FieldDefinition(BundleObjectDefinition):
    def __init__(self, prop_type, prop_name=None):
        super().__init__(obj_type=prop_type, name=prop_name)
        self["required"] = False


@allure.step('Wait for a new window after action')
@contextmanager
def wait_for_new_window(driver: WebDriver, wait_time: int = 10):
    """Wait a new window is opened after some action"""

    tabs = driver.window_handles
    yield
    WDW(driver, wait_time).until(EC.new_window_is_opened(tabs))
    tabs = driver.window_handles
    driver.switch_to.window(tabs[len(tabs) - 1])


@allure.step('Close current tab')
def close_current_tab(driver: WebDriver):
    """Close current tab and switch to first tab"""

    tabs = driver.window_handles
    driver.close()
    driver.switch_to.window(tabs[0])


def check_rows_amount(page, expected_amount: int, table_page_num: int):
    """
    Check rows count is equal to expected
    :param page: Page object with table attribute
    :param expected_amount: Expected amount of rows in table on that page
    :param table_page_num: Number of the current page (for assertion error message)
    """
    assert (
        row_count := page.table.row_count
    ) == expected_amount, f'Page #{table_page_num} should contain {expected_amount}, not {row_count}'


# !===== UI Information Comparator Function =====!


def is_equal(first_value: ValueType, second_value: ValueType) -> bool:
    """Check if two values are equal (==)"""
    return first_value == second_value


def is_empty(first_value: ValueType) -> bool:
    """Check if first value is empty (=='')"""
    return first_value == ''


def is_not_empty(first_value: ValueType) -> bool:
    """Check if first value is not empty (!='')"""
    return first_value != ''


def wait_and_assert_ui_info(
    expected_values: Dict[
        str,
        Union[
            Union[ValueType, Callable[[ValueType], bool]],
            Tuple[ValueType, Callable[[ValueType, ValueType], bool]],
        ],
    ],
    get_info_func: Union[Callable[[Any], FuncType]],
    get_info_kwargs: Optional[dict] = None,
    timeout: Union[int, float] = 5,
    period: Union[int, float] = 0.5,
):
    """
    Wait for some information on UI to be correct.
    Use it to avoid getting data from UI a bit earlier than it is fully loaded.

    As dict value for `expected_values` argument you can provide:

    - simple value to pass it to "is_equal" function as expected value;
    - tuple with expected value and callable that takes two arguments;
    - callable that takes exactly 1 argument (actual value).
    Callable should return bool and in case only callable is provided
    it's name is used in assertion message.

    :param expected_values: Dictionary with values that are expected to be found
                            in UI information object.
    :param get_info_func: Function to get UI information object.
    :param get_info_kwargs: Dictionary with keyword arguments to pass to `get_info_func`.
    :param timeout: Timeout for retries.
    :param period: Period between retries.
    """
    get_info_kwargs = get_info_kwargs or {}
    info = get_info_func(**get_info_kwargs)
    # to make assertion message more verbal
    ui_info_classname = info.__class__.__name__
    human_key_names = {k: k.replace("_", " ").capitalize() for k in expected_values.keys()}

    def check_info_from_ui():
        ui_info: FuncType = get_info_func(**get_info_kwargs)
        for key, value in expected_values.items():
            actual_value = ui_info[key] if isinstance(ui_info, dict) else getattr(ui_info, key)
            # we may want if out of loop someday
            if callable(value):
                # expected callable with 1 argument like 'is_empty', etc.
                compare_func = value
                assert compare_func(actual_value), (
                    f'{human_key_names[key]} in {ui_info_classname} '
                    f'failed to pass check "{compare_func.__name__}", '
                    f'actual value is {actual_value}'
                )
                return
            if isinstance(value, tuple):
                expected_value, compare_func = value
            else:
                expected_value = value
                compare_func = is_equal
            assert compare_func(actual_value, expected_value), (
                f'{human_key_names[key]} in {ui_info_classname} ' f'should be {expected_value}, not {actual_value}'
            )

    with allure.step('Check information is correct on UI'):
        wait_until_step_succeeds(check_info_from_ui, timeout=timeout, period=period)


def check_host_value(key: str, actual_value, expected_value):
    """
    Assert that actual value equals to expected value
    Argument `key` is used in failed assertion message
    """
    assert actual_value == expected_value, f"Host {key} should be {expected_value}, not {actual_value}"


def assert_enough_rows(required_row_num: int, row_count: int):
    """
    Assert that row "is presented" by comparing row index and amount of rows
    Provide row as index (starting with 0)
    """
    assert (
        required_row_num + 1 <= row_count
    ), f"Table has only {row_count} rows when row #{required_row_num} was requested"


@allure.step('Wait file {filename} is presented in directory {dirname}')
def wait_file_is_presented(
    app_fs: ADCMTest,
    filename: str,
    timeout: Union[int, float] = 70,
    period: Union[int, float] = 1,
):
    """Checks if file is presented in directory"""
    dir_url = f'http://{app_fs.selenoid["host"]}:{app_fs.selenoid["port"]}/download/{app_fs.driver.session_id}'
    file_url = f'{dir_url}/{filename}'

    def check_file_is_presented():
        dir_response = requests.get(dir_url)
        response = requests.get(file_url)
        assert response.status_code < 400, (
            f'Request for file ended with {response.status_code}, file request text: {response.text}. '
            f'Directory request finished with {dir_response.status_code} and text: {dir_response.text}'
        )

    wait_until_step_succeeds(check_file_is_presented, timeout=timeout, period=period)


@allure.step('Check that all fields and groups invisible')
def check_that_all_fields_and_groups_invisible(sdk_client: ADCMClient, path, app):
    """Prepare cluster from `path` and check that all fields and groups invisible."""

    _, config = prepare_cluster_and_get_config(sdk_client, path, app)

    fields = config.get_field_groups()
    for field in fields:
        assert not field.is_displayed(), f"Field should be invisible. Field classes: {field.get_attribute('class')}"
    group_names = config.get_group_elements()
    assert not group_names, "Group elements should be invisible"
    config.show_advanced()
    assert config.advanced, "Advanced fields should be expanded"
    fields = config.get_field_groups()
    group_names = config.get_group_elements()
    assert not group_names, "Advanced group elements should ve invisible"
    for field in fields:
        assert (
            not field.is_displayed()
        ), f"Advanced field should be invisible. Field classes: {field.get_attribute('class')}"


@contextmanager
def expect_rows_amount_change(get_all_rows: Callable[[], Sized]):
    """Waits for row count to be changed"""
    current_amount = len(get_all_rows())

    yield

    def check_rows_amount_is_changed():
        assert len(get_all_rows()) != current_amount, "Amount of rows on the page hasn't changed"

    wait_until_step_succeeds(check_rows_amount_is_changed, period=1, timeout=10)
