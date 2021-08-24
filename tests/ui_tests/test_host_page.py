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

# pylint:disable=redefined-outer-name
import os
from typing import (
    List,
    Tuple,
    Optional,
)

import allure
import pytest
from _pytest.fixtures import SubRequest
from adcm_client.objects import (
    ADCMClient,
    Bundle,
    Provider,
    Cluster,
)
from adcm_pytest_plugin import utils

from tests.ui_tests.app.app import ADCMTest
from tests.ui_tests.app.helpers.locator import Locator
from tests.ui_tests.app.page.admin_intro.page import AdminIntroPage
from tests.ui_tests.app.page.common.base_page import BasePageObject
from tests.ui_tests.app.page.common.configuration.locators import CommonConfigMenu
from tests.ui_tests.app.page.host.locators import (
    HostLocators,
    HostActionsLocators,
)
from tests.ui_tests.app.page.host.page import (
    HostMainPage,
    HostActionsPage,
    HostConfigPage,
)
from tests.ui_tests.app.page.host_list.locators import HostListLocators
from tests.ui_tests.app.page.host_list.page import HostListPage
from tests.ui_tests.app.page.host_list.page import HostRowInfo
from tests.ui_tests.utils import wait_and_assert_ui_info
from .utils import check_host_value

# defaults
HOST_FQDN = 'best-host'
CLUSTER_NAME = 'Best Cluster Ever'
PROVIDER_NAME = 'Black Mark'

INIT_ACTION = 'Init'

# config fields
REGULAR_FIELD_ADCM_TEST = 'just_item/just_item'
REQUIRED_FIELD_ADCM_TEST = 'required_item/required_item'
PASSWORD_FIELD_ADCM_TEST = 'important_password'
ADVANCED_FIELD_ADCM_TEST = 'advanced_one'


@pytest.fixture(params=["provider"])
@allure.title("Upload provider bundle")
def provider_bundle(request: SubRequest, sdk_client_fs: ADCMClient) -> Bundle:
    return sdk_client_fs.upload_from_fs(os.path.join(utils.get_data_dir(__file__), request.param))


@pytest.fixture()
@allure.title("Create provider")
def upload_and_create_provider(provider_bundle) -> Tuple[Bundle, Provider]:
    provider = provider_bundle.provider_create(PROVIDER_NAME)
    return provider_bundle, provider


@pytest.fixture()
@allure.title("Create host")
def _create_host(upload_and_create_provider: Tuple[Bundle, Provider]):
    """Create default host using API"""
    provider = upload_and_create_provider[1]
    provider.host_create(HOST_FQDN)


@pytest.fixture()
@allure.title("Create many hosts")
def _create_many_hosts(request, upload_and_create_provider):
    """Pass amount in param"""
    provider = upload_and_create_provider[1]
    for i in range(request.param):
        provider.host_create(f'no-fantasy-{i}')


@pytest.fixture()
def _create_bonded_host(
    upload_and_create_cluster: Tuple[Bundle, Cluster],
    upload_and_create_provider: Tuple[Bundle, Provider],
):
    """Create host bonded to cluster"""
    provider = upload_and_create_provider[1]
    host = provider.host_create(HOST_FQDN)
    cluster = upload_and_create_cluster[1]
    cluster.host_add(host)


@pytest.fixture()
@allure.title("Upload cluster bundle")
def cluster_bundle(sdk_client_fs: ADCMClient) -> Bundle:
    return sdk_client_fs.upload_from_fs(os.path.join(utils.get_data_dir(__file__), "cluster"))


@pytest.fixture()
@allure.title("Create cluster")
def upload_and_create_cluster(cluster_bundle: Bundle) -> Tuple[Bundle, Cluster]:
    cluster = cluster_bundle.cluster_prototype().cluster_create(CLUSTER_NAME)
    return cluster_bundle, cluster


@pytest.fixture()
# pylint: disable-next=unused-argument
def page(app_fs: ADCMTest, login_to_adcm_over_api) -> HostListPage:
    return HostListPage(app_fs.driver, app_fs.adcm.url).open()


@allure.step("Check elements aren't visible")
def elements_should_be_hidden(page: BasePageObject, locators: List[Locator]):
    # should be faster than alternatives to not is_visible and stuff
    for loc in locators:
        page.check_element_should_be_hidden(loc)


@allure.step('Open host config menu from host list')
def open_config(page) -> HostConfigPage:
    page.click_on_row_child(0, HostListLocators.HostTable.HostRow.config)
    return HostConfigPage(page.driver, page.base_url, 1, None)


def check_job_name(sdk: ADCMClient, action_display_name: str):
    """Check job with correct name is launched"""
    jobs_display_names = {job.display_name for job in sdk.job_list()}
    assert action_display_name in jobs_display_names, (
        f'Action with name "{action_display_name}" was not ran. ' f'Job names found: {jobs_display_names}'
    )


def check_host_info(host_info: HostRowInfo, fqdn: str, provider: str, cluster: Optional[str], state: str):
    """Check all values in host info"""
    check_host_value('FQDN', host_info.fqdn, fqdn)
    check_host_value('provider', host_info.provider, provider)
    check_host_value('cluster', host_info.cluster, cluster)
    check_host_value('state', host_info.state, state)


def _check_menu(
    menu_name: str,
    provider_bundle: Bundle,
    list_page: HostListPage,
):
    list_page.click_on_row_child(0, HostListLocators.HostTable.HostRow.fqdn)
    host_page = HostMainPage(list_page.driver, list_page.base_url, 1, None)
    getattr(host_page, f'open_{menu_name}_menu')()
    host_page.check_fqdn_equal_to(HOST_FQDN)
    bundle_label = host_page.get_bundle_label()
    # Test Host is name of host in config.yaml
    assert 'Test Host' in bundle_label
    assert provider_bundle.version in bundle_label


# !===== TESTS =====!


@pytest.mark.parametrize(
    "bundle_archive",
    [utils.get_data_dir(__file__, "provider")],
    indirect=True,
    ids=['provider_bundle'],
)
def test_create_host_with_bundle_upload(page: HostListPage, bundle_archive: str):
    """Upload bundle and create host"""
    host_fqdn = 'howdy-host-fqdn'
    page.open_host_creation_popup()
    new_provider_name = page.host_popup.create_provider_and_host(bundle_archive, host_fqdn)
    expected_values = {
        'fqdn': host_fqdn,
        'provider': new_provider_name,
        'cluster': None,
        'state': 'created',
    }
    wait_and_assert_ui_info(
        expected_values,
        page.get_host_info_from_row,
    )


@pytest.mark.usefixtures("upload_and_create_provider", "upload_and_create_cluster")
def test_create_bonded_to_cluster_host(page: HostListPage):
    """Create host bonded to cluster"""
    host_fqdn = 'cluster-host'
    expected_values = {
        'fqdn': host_fqdn,
        'provider': PROVIDER_NAME,
        'cluster': CLUSTER_NAME,
        'state': 'created',
    }
    page.open_host_creation_popup()
    page.host_popup.create_host(host_fqdn, cluster=CLUSTER_NAME)
    wait_and_assert_ui_info(
        expected_values,
        page.get_host_info_from_row,
    )


@pytest.mark.full()
@pytest.mark.parametrize("_create_many_hosts", [12], indirect=True)
@pytest.mark.usefixtures("_create_many_hosts")
def test_host_list_pagination(page: HostListPage):
    """Create more than 10 hosts and check pagination"""
    hosts_on_second_page = 2
    page.close_info_popup()
    page.table.check_pagination(hosts_on_second_page)


@pytest.mark.usefixtures("upload_and_create_provider", "upload_and_create_cluster")
def test_bind_host_to_cluster(page: HostListPage):
    """Create host and go to cluster from host list"""
    expected_values = {
        'fqdn': HOST_FQDN,
        'provider': PROVIDER_NAME,
        'cluster': None,
        'state': 'created',
    }
    page.open_host_creation_popup()
    page.host_popup.create_host(HOST_FQDN)
    with allure.step("Check host is created and isn't bound to a cluster"):
        wait_and_assert_ui_info(
            expected_values,
            page.get_host_info_from_row,
        )
    page.bind_host_to_cluster(0, CLUSTER_NAME)
    page.assert_host_bonded_to_cluster(0, CLUSTER_NAME)


@pytest.mark.parametrize(
    ('row_child_name', 'menu_item_name'),
    [
        pytest.param('fqdn', 'main_tab', id='open_host_main'),
        pytest.param('status', 'status_tab', id='open_status_menu', marks=pytest.mark.full),
        pytest.param('config', 'config_tab', id='open_config_menu', marks=pytest.mark.full),
    ],
)
@pytest.mark.usefixtures('_create_host')
def test_open_host_from_host_list(
    page: HostListPage,
    row_child_name: str,
    menu_item_name: str,
):
    """Test open host page from host list"""
    row_child = getattr(HostListLocators.HostTable.HostRow, row_child_name)
    menu_item_locator = getattr(HostLocators.MenuNavigation, menu_item_name)
    page.click_on_row_child(0, row_child)
    main_host_page = HostMainPage(page.driver, page.base_url, 1, None)
    with allure.step('Check correct menu is opened'):
        main_host_page.check_fqdn_equal_to(HOST_FQDN)
        assert main_host_page.active_menu_is(menu_item_locator)


@pytest.mark.usefixtures("_create_host", "upload_and_create_provider")
def test_delete_host(page: HostListPage):
    """Create host and delete it"""
    expected_values = {
        'fqdn': HOST_FQDN,
        'provider': PROVIDER_NAME,
        'cluster': None,
        'state': 'created',
    }
    wait_and_assert_ui_info(expected_values, page.get_host_info_from_row)
    page.delete_host(0)
    page.check_element_should_be_hidden(HostListLocators.HostTable.row)


@pytest.mark.usefixtures("_create_bonded_host")
def test_delete_bonded_host(page: HostListPage):
    """Host shouldn't be deleted"""
    page.check_element_should_be_visible(HostListLocators.HostTable.row)
    page.open_host_creation_popup()
    page.host_popup.create_host(HOST_FQDN, cluster=CLUSTER_NAME)
    page.delete_host(0)
    page.check_element_should_be_visible(HostListLocators.HostTable.row)


@pytest.mark.full()
@pytest.mark.parametrize('menu', ['main', 'config', 'status', 'action'])
@pytest.mark.usefixtures('_create_host')
def test_open_menu(
    upload_and_create_provider: Tuple[Bundle, Provider],
    page: HostListPage,
    menu: str,
):
    """Open main page and open menu from side navigation"""
    _check_menu(menu, upload_and_create_provider[0], page)


@pytest.mark.usefixtures('_create_host')
def test_run_action_on_new_host(
    page: HostListPage,
):
    """Create host and run action on it"""
    page.assert_host_state(0, 'created')
    page.run_action(0, INIT_ACTION)
    page.assert_host_state(0, 'running')


@pytest.mark.usefixtures('_create_host')
def test_run_action_from_menu(
    sdk_client_fs: ADCMClient,
    page: HostListPage,
):
    """Run action from host actions menu"""
    page.click_on_row_child(0, HostListLocators.HostTable.HostRow.fqdn)
    host_main_page = HostMainPage(page.driver, page.base_url, 1, None)
    actions_page: HostActionsPage = host_main_page.open_action_menu()
    actions_before = actions_page.get_action_names()
    assert INIT_ACTION in actions_before, f'Action {INIT_ACTION} should be listed in Actions menu'
    with allure.step('Run action "Init" from host Actions menu'):
        actions_page.open_action_menu()
        actions_page.run_action_from_menu(INIT_ACTION)
        actions_page.wait_element_hide(HostActionsLocators.action_btn(INIT_ACTION))
        check_job_name(sdk_client_fs, INIT_ACTION)
        actions_page.wait_element_clickable(HostActionsLocators.action_run_btn, timeout=10)
    actions_page.open_action_menu()
    actions_after = actions_page.get_action_names()
    with allure.step('Assert available actions set changed'):
        assert actions_before != actions_after, 'Action set did not change after "Init" action'


@pytest.mark.full()
@pytest.mark.parametrize('provider_bundle', ["provider_config"], indirect=True)
@pytest.mark.usefixtures('_create_host')
def test_filter_config(
    page: HostListPage,
):
    """Use filters on host configuration page"""
    params = {'group': 'group_one', 'search_text': 'Adv'}
    host_page = open_config(page)
    field_input = CommonConfigMenu.field_input
    not_required_option = field_input(REGULAR_FIELD_ADCM_TEST)
    required_option = field_input(REQUIRED_FIELD_ADCM_TEST)
    password_fields = CommonConfigMenu.password_inputs(PASSWORD_FIELD_ADCM_TEST)
    advanced_option = field_input(ADVANCED_FIELD_ADCM_TEST)
    with allure.step('Check unfiltered configuration'):
        host_page.assert_displayed_elements([not_required_option, required_option, password_fields])
        assert not host_page.is_element_displayed(advanced_option), 'Advanced option should not be visible'
    with allure.step('Check group roll up'):
        host_page.config.click_on_group(params['group'])
        elements_should_be_hidden(host_page, [not_required_option, required_option])
        host_page.is_element_displayed(password_fields)
        host_page.config.click_on_group(params['group'])
        host_page.check_element_should_be_visible(not_required_option)
    with allure.step('Check configuration with "Advanced" turned on'):
        host_page.find_and_click(CommonConfigMenu.advanced_label)
        host_page.check_element_should_be_visible(advanced_option)
        host_page.assert_displayed_elements([not_required_option, required_option, password_fields])
    with allure.step('Check search filtration'):
        host_page.config.search(params['search_text'])
        host_page.is_element_displayed(advanced_option)
        elements_should_be_hidden(host_page, [not_required_option, required_option, password_fields])
        host_page.find_and_click(CommonConfigMenu.advanced_label)
        host_page.check_element_should_be_hidden(advanced_option)


@pytest.mark.parametrize('provider_bundle', ["provider_config"], indirect=True)
@pytest.mark.usefixtures('_create_host')
def test_custom_name_config(
    page: HostListPage,
):
    """Change configuration, save with custom name, compare changes"""
    params = {
        'password': 'awesomepass',
        'description': 'my own config description',
        'type_in_required': '12',
        'required_expected': '',
        'password_expected': '***',
    }
    host_page = open_config(page)
    with allure.step('Change config description'):
        init_config_desc = host_page.config.set_description(params['description'])
    with allure.step('Change config values'):
        host_page.config.type_in_config_field(params['type_in_required'], REQUIRED_FIELD_ADCM_TEST)
        host_page.config.fill_password_and_confirm_fields(
            params['password'], params['password'], adcm_test=PASSWORD_FIELD_ADCM_TEST
        )
        host_page.config.save_config()
    with allure.step('Compare configurations'):
        host_page.config.compare_current_to(init_config_desc)
        host_page.config.config_diff_is_presented(params['required_expected'], REQUIRED_FIELD_ADCM_TEST)
        host_page.config.config_diff_is_presented(params['password_expected'], PASSWORD_FIELD_ADCM_TEST)


@pytest.mark.full()
@pytest.mark.parametrize('provider_bundle', ["provider_config"], indirect=True)
@pytest.mark.usefixtures('_create_host')
def test_reset_configuration(
    page: HostListPage,
):
    """Change configuration, save, reset to defaults"""
    params = {
        'pass_adcm_test': PASSWORD_FIELD_ADCM_TEST,
        'req_field_adcm_test': REQUIRED_FIELD_ADCM_TEST,
        'password': 'pass',
        'type_in_req_field': '42',
        'init_value': '',
    }
    host_page = open_config(page)
    host_page.config.fill_password_and_confirm_fields(
        params['password'], params['password'], adcm_test=params['pass_adcm_test']
    )
    host_page.config.type_in_config_field(
        params['type_in_req_field'], adcm_test=params['req_field_adcm_test'], clear=True
    )
    host_page.config.save_config()
    host_page.config.reset_to_default(params['req_field_adcm_test'])
    host_page.config.assert_input_value_is(params['init_value'], params['req_field_adcm_test'])
    host_page.config.reset_to_default(params['pass_adcm_test'])
    host_page.config.assert_input_value_is(params['init_value'], params['pass_adcm_test'], is_password=True)


@pytest.mark.full()
@pytest.mark.parametrize('provider_bundle', ["provider_config"], indirect=True)
@pytest.mark.usefixtures('_create_host')
def test_field_validation(
    page: HostListPage,
):
    """Inputs are validated correctly"""
    params = {
        'pass_name': 'Important password',
        'req_name': 'Required item',
        'not_req_name': 'Just item',
        'wrong_value': 'etonechislo',
    }
    host_page = open_config(page)
    host_page.wait_element_visible(host_page.config.config.field_input(REGULAR_FIELD_ADCM_TEST))
    host_page.config.check_password_confirm_required(params['pass_name'])
    host_page.config.check_field_is_required(params['req_name'])
    host_page.config.type_in_config_field(params['wrong_value'], REGULAR_FIELD_ADCM_TEST)
    host_page.config.check_field_is_invalid(params['not_req_name'])


@pytest.mark.full()
@pytest.mark.usefixtures('_create_host')
def test_open_adcm_main_menu(page: HostListPage):
    """Open main menu by clicking on the menu icon in toolbar"""
    page.find_and_click(HostListLocators.Tooltip.apps_btn)
    AdminIntroPage(page.driver, page.base_url).wait_url_contains_path("/admin/intro")
