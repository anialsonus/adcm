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

"""Tests for activatable groups"""

import allure
import pytest
from adcm_client.objects import ADCMClient
from adcm_pytest_plugin.utils import parametrize_by_data_subdirs

from .utils import prepare_cluster_and_get_config, check_that_all_fields_and_groups_invisible

pytestmark = [pytest.mark.usefixtures("login_to_adcm_over_api")]


@allure.step('Check that field is invisible if group is active or not')
def _check_that_field_is_invisible_if_group_active_or_not(sdk_client: ADCMClient, path, app):
    """Check that field is invisible if group is active or not."""

    _, config = prepare_cluster_and_get_config(sdk_client, path, app)

    group_name = path.split("/")[-1]
    with allure.step('Check that field is visible if group is not active'):
        group_active = config.group_is_active_by_name(group_name)
        assert not group_active
        fields = config.get_field_groups()
        for field in fields:
            assert not field.is_displayed(), field.get_attribute("class")
        group_names = config.get_group_elements()
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        assert group_names, group_names
        config.show_advanced()
        assert config.advanced
    with allure.step('Check that field is invisible if group is active'):
        config.activate_group_by_name(group_name)
        group_active = config.group_is_active_by_name(group_name)
        assert group_active
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert not field.is_displayed(), field.get_attribute("class")


@allure.step('Check that field invisible if activatable group active and not')
def _check_that_field_invisible_if_activatable_group_active_and_not(sdk_client: ADCMClient, path, app):
    """Check that field invisible if activatable group active and not."""

    _, config = prepare_cluster_and_get_config(sdk_client, path, app)
    group_name = path.split("/")[-1]
    with allure.step('Check that field is visible if activatable group is not active'):
        group_active = config.group_is_active_by_name(group_name)
        assert group_active
        fields = config.get_field_groups()
        for field in fields:
            assert not field.is_displayed(), field.get_attribute("class")
        group_names = config.get_group_elements()
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        assert group_names, group_names
    config.show_advanced()
    assert config.advanced
    with allure.step('Check that field invisible if activatable group active'):
        config.activate_group_by_name(group_name)
        group_active = config.group_is_active_by_name(group_name)
        assert group_active
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert not field.is_displayed(), field.get_attribute("class")


@allure.step('Check that field is visible if advanced and activatable true')
def _check_that_all_field_is_visible_if_advanced_and_activatable_true(sdk_client: ADCMClient, path, app):
    """Field visible if advanced and activatable true"""

    _, config = prepare_cluster_and_get_config(sdk_client, path, app)
    group_name = path.split("/")[-1]
    with allure.step('Check that field is visible if advanced and activatable'):
        config.check_that_fields_and_group_are_invisible()
        config.show_advanced()
        assert config.advanced
        config.activate_group_by_name(group_name)
        group_active = config.group_is_active_by_name(group_name)
        assert group_active
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert field.is_displayed(), field.get_attribute("class")


@allure.step('Check that field invisible')
def _check_that_all_field_is_invisible(sdk_client: ADCMClient, path, app):
    """Check that field invisible"""

    _, config = prepare_cluster_and_get_config(sdk_client, path, app)
    group_name = path.split("/")[-1]
    with allure.step('Check that field invisible'):
        config.check_that_fields_and_group_are_invisible()
        config.show_advanced()
        assert config.advanced
        group_active = config.group_is_active_by_name(group_name)
        assert group_active
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert not field.is_displayed(), field.get_attribute("class")


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_false_field_advanced_false_invisible_false_activiatable_false",
)
def test_group_advanced_false_invisible_false_field_advanced_false_invisible_false_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that group not active and field is invisible until group is not active."""

    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    group_name = path.split("/")[-1]
    with allure.step('Check that group not active and field is invisible'):
        group_active = config.group_is_active_by_name(group_name)
        assert not group_active
        fields = config.get_field_groups()
        for field in fields:
            assert not field.is_displayed(), field.get_attribute("class")
        group_names = config.get_group_elements()
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        assert group_names, group_names
        config.show_advanced()
        assert config.advanced
    config.activate_group_by_name(group_name)
    group_active = config.group_is_active_by_name(group_name)
    with allure.step('Check that group is active and field is visible'):
        assert group_active
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert field.is_displayed(), field.get_attribute("class")


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_false_field_advanced_false_invisible_false_activiatable_true",
)
def test_group_advanced_false_invisible_false_field_advanced_false_invisible_false_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that group active and all fields always visible."""

    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    group_name = path.split("/")[-1]
    with allure.step('Check that group active and all fields always visible'):
        group_active = config.group_is_active_by_name(group_name)
        assert group_active
        fields = config.get_field_groups()
        for field in fields:
            assert field.is_displayed(), field.get_attribute("class")
        group_names = config.get_group_elements()
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        assert group_names, group_names
        config.show_advanced()
        assert config.advanced
    config.activate_group_by_name(group_name)
    group_active = config.group_is_active_by_name(group_name)
    with allure.step('Check that group active and fields are visible'):
        assert group_active
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert field.is_displayed(), field.get_attribute("class")


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_false_field_advanced_false_invisible_true_activiatable_false",
)
def test_group_advanced_false_invisible_false_field_advanced_false_invisible_true_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that field is invisible if group is active or not."""

    _check_that_field_is_invisible_if_group_active_or_not(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_false_field_advanced_false_invisible_true_activiatable_true",
)
def test_group_advanced_false_invisible_false_field_advanced_false_invisible_true_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that field invisible if activatable group active and not."""

    _check_that_field_invisible_if_activatable_group_active_and_not(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_false_field_advanced_true_invisible_false_activiatable_false",
)
def test_group_advanced_false_invisible_false_field_advanced_true_invisible_false_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that field visible if advanced group is enabled."""

    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    group_name = path.split("/")[-1]
    with allure.step('Check that group not active'):
        group_active = config.group_is_active_by_name(group_name)
        assert not group_active
        fields = config.get_field_groups()
        for field in fields:
            assert not field.is_displayed(), field.get_attribute("class")
        group_names = config.get_group_elements()
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        assert group_names, group_names
    config.show_advanced()
    assert config.advanced
    config.activate_group_by_name(group_name)
    group_active = config.group_is_active_by_name(group_name)
    with allure.step('Check that field visible if advanced group is enabled'):
        assert group_active
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert field.is_displayed(), field.get_attribute("class")


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_false_field_advanced_true_invisible_false_activiatable_true",
)
def test_group_advanced_false_invisible_false_field_advanced_true_invisible_false_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that field is visible if group active and advanced enabled."""

    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    group_name = path.split("/")[-1]
    group_active = config.group_is_active_by_name(group_name)
    with allure.step('Check that group is active'):
        assert group_active
        fields = config.get_field_groups()
        for field in fields:
            assert not field.is_displayed(), field.get_attribute("class")
        group_names = config.get_group_elements()
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        assert group_names, group_names
    config.show_advanced()
    assert config.advanced
    config.activate_group_by_name(group_name)
    group_active = config.group_is_active_by_name(group_name)
    with allure.step('Check that field is visible if group active and advanced enabled'):
        assert group_active
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert field.is_displayed(), field.get_attribute("class")


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_false_field_advanced_true_invisible_true_activiatable_false",
)
def test_group_advanced_false_invisible_false_field_advanced_true_invisible_true_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that field is invisible if group is active or not."""

    _check_that_field_is_invisible_if_group_active_or_not(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_false_field_advanced_true_invisible_true_activiatable_true",
)
def test_group_advanced_false_invisible_false_field_advanced_true_invisible_true_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that field invisible if activatable group active and not."""

    _check_that_field_invisible_if_activatable_group_active_and_not(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_true_field_advanced_false_invisible_false_activiatable_false",
)
def test_group_advanced_false_invisible_true_field_advanced_false_invisible_false_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_true_field_advanced_false_invisible_false_activiatable_true",
)
def test_group_advanced_false_invisible_true_field_advanced_false_invisible_false_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_true_field_advanced_false_invisible_true_activiatable_false",
)
def test_group_advanced_false_invisible_true_field_advanced_false_invisible_true_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_true_field_advanced_false_invisible_true_activiatable_true",
)
def test_group_advanced_false_invisible_true_field_advanced_false_invisible_true_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_true_field_advanced_true_invisible_false_activiatable_false",
)
def test_group_advanced_false_invisible_true_field_advanced_true_invisible_false_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_true_field_advanced_true_invisible_false_activiatable_true",
)
def test_group_advanced_false_invisible_true_field_advanced_true_invisible_false_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_true_field_advanced_true_invisible_true_activiatable_false",
)
def test_group_advanced_false_invisible_true_field_advanced_true_invisible_true_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_false_invisible_true_field_advanced_true_invisible_true_activiatable_true",
)
def test_group_advanced_false_invisible_true_field_advanced_true_invisible_true_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_false_field_advanced_false_invisible_false_activiatable_false",
)
def test_group_advanced_true_invisible_false_field_advanced_false_invisible_false_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Field visible if advanced and activatable true."""

    _check_that_all_field_is_visible_if_advanced_and_activatable_true(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_false_field_advanced_false_invisible_false_activiatable_true",
)
def test_group_advanced_true_invisible_false_field_advanced_false_invisible_false_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Field visible if advanced and activatable true."""

    _check_that_all_field_is_visible_if_advanced_and_activatable_true(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_false_field_advanced_false_invisible_true_activiatable_false",
)
def test_group_advanced_true_invisible_false_field_advanced_false_invisible_true_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Field invisible, group visible if advanced."""

    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    group_name = path.split("/")[-1]
    config.check_that_fields_and_group_are_invisible()
    config.show_advanced()
    assert config.advanced
    group_active = config.group_is_active_by_name(group_name)
    assert not group_active
    config.activate_group_by_name(group_name)
    group_active = config.group_is_active_by_name(group_name)
    assert group_active
    with allure.step('Check that fields and group are visible'):
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert not field.is_displayed(), field.get_attribute("class")


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_false_field_advanced_false_invisible_true_activiatable_true",
)
def test_group_advanced_true_invisible_false_field_advanced_false_invisible_true_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that field invisible."""

    _check_that_all_field_is_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_false_field_advanced_true_invisible_false_activiatable_false",
)
def test_group_advanced_true_invisible_false_field_advanced_true_invisible_false_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that field and group visible if advanced button clicked."""

    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    group_name = path.split("/")[-1]
    config.check_that_fields_and_group_are_invisible()
    config.show_advanced()
    assert config.advanced
    group_active = config.group_is_active_by_name(group_name)
    assert not group_active
    config.activate_group_by_name(group_name)
    group_active = config.group_is_active_by_name(group_name)
    assert group_active
    with allure.step('Check that field and group visible if advanced button clicked'):
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert field.is_displayed(), field.get_attribute("class")


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_false_field_advanced_true_invisible_false_activiatable_true",
)
def test_group_advanced_true_invisible_false_field_advanced_true_invisible_false_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that field visible if advanced clicked."""

    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    group_name = path.split("/")[-1]
    config.check_that_fields_and_group_are_invisible()
    config.show_advanced()
    assert config.advanced
    group_active = config.group_is_active_by_name(group_name)
    assert group_active
    with allure.step('Check that field visible if advanced clicked'):
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert field.is_displayed(), field.get_attribute("class")


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_false_field_advanced_true_invisible_true_activiatable_false",
)
def test_group_advanced_true_invisible_false_field_advanced_true_invisible_true_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Field always invisible."""

    _, config = prepare_cluster_and_get_config(sdk_client_fs, path, app_fs)
    group_name = path.split("/")[-1]
    config.check_that_fields_and_group_are_invisible()
    config.show_advanced()
    assert config.advanced
    config.activate_group_by_name(group_name)
    group_active = config.group_is_active_by_name(group_name)
    assert group_active
    with allure.step('Check that fields are always invisible'):
        group_names = config.get_group_elements()
        assert group_names, group_names
        assert len(group_names) == 1
        assert group_names[0].text == group_name
        fields = config.get_field_groups()
        for field in fields:
            assert not field.is_displayed(), field.get_attribute("class")


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_false_field_advanced_true_invisible_true_activiatable_true",
)
def test_group_advanced_true_invisible_false_field_advanced_true_invisible_true_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that field invisible."""

    _check_that_all_field_is_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_true_field_advanced_false_invisible_false_activiatable_false",
)
def test_group_advanced_true_invisible_true_field_advanced_false_invisible_false_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible.."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_true_field_advanced_false_invisible_false_activiatable_true",
)
def test_group_advanced_true_invisible_true_field_advanced_false_invisible_false_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_true_field_advanced_false_invisible_true_activiatable_false",
)
def test_group_advanced_true_invisible_true_field_advanced_false_invisible_true_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_true_field_advanced_true_invisible_false_activiatable_false",
)
def test_group_advanced_true_invisible_true_field_advanced_true_invisible_false_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_true_field_advanced_false_invisible_true_activiatable_true",
)
def test_group_advanced_true_invisible_true_field_advanced_false_invisible_true_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_true_field_advanced_true_invisible_false_activiatable_true",
)
def test_group_advanced_true_invisible_true_field_advanced_true_invisible_false_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_true_field_advanced_true_invisible_true_activiatable_false",
)
def test_group_advanced_true_invisible_true_field_advanced_true_invisible_true_active_false(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)


@parametrize_by_data_subdirs(
    __file__,
    "group_advanced_true_invisible_true_field_advanced_true_invisible_true_activiatable_true",
)
def test_group_advanced_true_invisible_true_field_advanced_true_invisible_true_active_true(
    sdk_client_fs: ADCMClient, path, app_fs
):
    """Check that all fields and groups invisible."""

    check_that_all_fields_and_groups_invisible(sdk_client_fs, path, app_fs)
