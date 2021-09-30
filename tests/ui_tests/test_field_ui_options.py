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

"""Test UI options for config fields"""

import allure
import pytest
from adcm_client.objects import ADCMClient
from adcm_pytest_plugin.utils import parametrize_by_data_subdirs

from tests.ui_tests.utils import prepare_cluster_and_get_config

pytestmark = [pytest.mark.usefixtures("login_to_adcm_over_api")]


@parametrize_by_data_subdirs(__file__, "invisible_true", 'advanced_true')
def test_ui_option_invisible_true_advanced_true(sdk_client_fs: ADCMClient, path, app_fs):
    """Test field visualisation with invisible=true advanced=true"""
    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    groups = config.get_field_groups()
    with allure.step("Check that we haven't invisible fields on UI"):
        for group in groups:
            assert not group.is_displayed(), group.get_attribute("class")


@parametrize_by_data_subdirs(__file__, "invisible_true", 'advanced_false')
def test_ui_option_invisible_true_advanced_false(sdk_client_fs: ADCMClient, path, app_fs):
    """Test field visualisation with invisible=true advanced=false"""
    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    config.show_advanced()
    assert config.advanced
    groups = config.get_field_groups()
    with allure.step("Check that we haven't invisible fields on UI if advanced field enabled"):
        for group in groups:
            assert not group.is_displayed(), group.get_attribute("class")


@parametrize_by_data_subdirs(__file__, "invisible_false", 'advanced_true')
def test_ui_option_invisible_false_advanced_true(sdk_client_fs: ADCMClient, path, app_fs):
    """Test field visualisation with invisible=false advanced=true"""
    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    groups = config.get_field_groups()
    config.hide_advanced()
    assert not config.advanced
    for group in groups:
        assert not group.is_displayed(), group.get_attribute("class")
    config.click_advanced()
    assert config.advanced
    groups = config.get_field_groups()
    with allure.step('Check that field is not visible by default but with enabled advanced visible'):
        for group in groups:
            assert group.is_displayed(), group.get_attribute("class")


@parametrize_by_data_subdirs(__file__, "invisible_false", 'advanced_false')
def test_ui_option_invisible_false_advanced_false(sdk_client_fs: ADCMClient, path, app_fs):
    """Test field visualisation with invisible=false advanced=false"""
    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    groups = config.get_field_groups()
    for group in groups:
        assert group.is_displayed(), group.get_attribute("class")
    config.show_advanced()
    groups = config.get_field_groups()
    with allure.step('Check that we can see groups with advanced option and without'):
        for group in groups:
            assert group.is_displayed(), group.get_attribute("class")
