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

"""UI tests for /provider page"""

import os

import allure
import pytest

from _pytest.fixtures import SubRequest
from adcm_client.objects import ADCMClient, Bundle, Provider
from adcm_pytest_plugin import utils

from tests.ui_tests.app.page.admin.page import AdminIntroPage
from tests.ui_tests.app.page.provider.page import ProviderMainPage, ProviderConfigPage
from tests.ui_tests.app.page.provider_list.page import ProviderListPage

# pylint: disable=redefined-outer-name,no-self-use,unused-argument,too-few-public-methods


pytestmark = pytest.mark.usefixtures("login_to_adcm_over_api")
PROVIDER_NAME = 'test_provider'


@pytest.fixture(params=["provider"])
@allure.title("Upload provider bundle")
def bundle(request: SubRequest, sdk_client_fs: ADCMClient) -> Bundle:
    """Upload provider bundle"""
    return sdk_client_fs.upload_from_fs(os.path.join(utils.get_data_dir(__file__), request.param))


@pytest.fixture()
@allure.title("Create provider from uploaded bundle")
def upload_and_create_test_provider(bundle) -> Provider:
    """Create provider from uploaded bundle"""
    return bundle.provider_create(PROVIDER_NAME)


class TestProviderListPage:
    """Tests for provider list page"""

    @pytest.mark.smoke()
    @pytest.mark.parametrize(
        "bundle_archive", [pytest.param(utils.get_data_dir(__file__, "provider"), id="provider")], indirect=True
    )
    def test_create_provider_on_provider_list_page(self, app_fs, bundle_archive):
        """Tests create provider from provider list page"""
        provider_params = {
            "bundle": "test_provider 2.15 community",
            "state": "created",
        }
        provider_page = ProviderListPage(app_fs.driver, app_fs.adcm.url).open()
        with allure.step("Check no provider rows"):
            assert len(provider_page.table.get_all_rows()) == 0, "There should be no row with providers"
        provider_page.create_provider(bundle=bundle_archive)
        with allure.step("Check uploaded provider"):
            rows = provider_page.table.get_all_rows()
            assert len(rows) == 1, "There should be 1 row with providers"
            uploaded_provider = provider_page.get_provider_info_from_row(rows[0])
            assert (
                provider_params['bundle'] == uploaded_provider.bundle
            ), f"Provider bundle should be {provider_params['bundle']} and not {uploaded_provider.bundle}"
            assert (
                provider_params['state'] == uploaded_provider.state
            ), f"Provider state should be {provider_params['state']} and not {uploaded_provider.state}"

    @pytest.mark.smoke()
    @pytest.mark.parametrize(
        "bundle_archive", [pytest.param(utils.get_data_dir(__file__, "provider"), id="provider")], indirect=True
    )
    def test_create_custom_provider_on_provider_list_page(self, app_fs, bundle_archive):
        """Tests create provider from provider list page with custom params"""
        provider_params = {
            "name": "Test Provider",
            "description": "Test",
            "bundle": "test_provider 2.15 community",
            "state": "created",
        }
        provider_page = ProviderListPage(app_fs.driver, app_fs.adcm.url).open()
        with provider_page.table.wait_rows_change():
            provider_page.create_provider(
                bundle=bundle_archive, name=provider_params['name'], description=provider_params['description']
            )
        with allure.step("Check uploaded provider"):
            rows = provider_page.table.get_all_rows()
            uploaded_provider = provider_page.get_provider_info_from_row(rows[0])
            assert (
                provider_params['bundle'] == uploaded_provider.bundle
            ), f"Provider bundle should be {provider_params['bundle']} and not {uploaded_provider.bundle}"
            assert (
                provider_params['name'] == uploaded_provider.name
            ), f"Provider name should be {provider_params['name']} and not {uploaded_provider.name}"

    def test_check_provider_list_page_pagination(self, bundle, app_fs):
        """Tests provider list pagination"""
        with allure.step("Create 11 providers"):
            for i in range(11):
                bundle.provider_create(name=f"Test provider {i}")
        provider_page = ProviderListPage(app_fs.driver, app_fs.adcm.url).open()
        provider_page.close_info_popup()
        provider_page.table.check_pagination(second_page_item_amount=1)

    @pytest.mark.smoke()
    @pytest.mark.usefixtures("upload_and_create_test_provider")
    def test_run_action_on_provider_list_page(self, app_fs):
        """Tests run action from provider list page"""
        params = {"action_name": "test_action", "expected_state": "installed"}
        provider_page = ProviderListPage(app_fs.driver, app_fs.adcm.url).open()
        row = provider_page.table.get_all_rows()[0]
        with provider_page.wait_provider_state_change(row):
            provider_page.run_action_in_provider_row(row, params["action_name"])
        with allure.step("Check provider state has changed"):
            assert (
                provider_page.get_provider_info_from_row(row).state == params["expected_state"]
            ), f"provider state should be {params['expected_state']}"
        with allure.step("Check success provider job"):
            assert (
                provider_page.header.get_success_job_amount_from_header() == "1"
            ), "There should be 1 success provider job in header"

    @pytest.mark.smoke()
    def test_open_config_from_provider_list_page(self, app_fs, upload_and_create_test_provider):
        """Tests open provider config from provider list page"""
        provider_page = ProviderListPage(app_fs.driver, app_fs.adcm.url).open()
        row = provider_page.table.get_all_rows()[0]
        provider_page.click_config_btn_in_row(row)
        ProviderConfigPage(app_fs.driver, app_fs.adcm.url, upload_and_create_test_provider.id).wait_page_is_opened()

    @pytest.mark.smoke()
    def test_open_main_from_provider_list_page(self, app_fs, upload_and_create_test_provider):
        """Tests open provider main page from provider list page"""
        provider_page = ProviderListPage(app_fs.driver, app_fs.adcm.url).open()
        row = provider_page.table.get_all_rows()[0]
        provider_page.click_name_in_row(row)
        ProviderMainPage(app_fs.driver, app_fs.adcm.url, upload_and_create_test_provider.id).wait_page_is_opened()

    @pytest.mark.smoke()
    @pytest.mark.usefixtures("upload_and_create_test_provider")
    def test_delete_provider_from_provider_list_page(self, app_fs):
        """Tests delete provider from provider list page"""
        provider_page = ProviderListPage(app_fs.driver, app_fs.adcm.url).open()
        row = provider_page.table.get_all_rows()[0]
        with provider_page.table.wait_rows_change():
            provider_page.delete_provider_in_row(row)
        with allure.step("Check there are no rows"):
            assert len(provider_page.table.get_all_rows()) == 0, "Provider table should be empty"

    @pytest.mark.smoke()
    def test_get_error_from_delete_provider_from_provider_list_page(self, app_fs, upload_and_create_test_provider):
        """Tests delete provider error from provider list page"""
        params = {
            "message": '[ CONFLICT ] PROVIDER_CONFLICT -- '
            'There is host #1 "test_host" of host provider #1 "test_provider"'
        }
        upload_and_create_test_provider.host_create("test_host")
        provider_page = ProviderListPage(app_fs.driver, app_fs.adcm.url).open()
        row = provider_page.table.get_all_rows()[0]
        provider_page.delete_provider_in_row(row)
        with allure.step("Check error message"):
            assert provider_page.get_info_popup_text() == params["message"], "No error message"

    @pytest.mark.usefixtures("upload_and_create_test_provider")
    def test_open_admin_page_by_toolbar_from_provider_list_page(self, app_fs):
        """Tests open admin page from provider list page"""
        provider_page = ProviderListPage(app_fs.driver, app_fs.adcm.url).open()
        provider_page.toolbar.click_admin_link()
        AdminIntroPage(app_fs.driver, app_fs.adcm.url).wait_page_is_opened()


class TestProviderMainPage:
    """Tests for provider main page"""

    @pytest.mark.smoke()
    def test_open_by_tab_provider_main_page(self, app_fs, upload_and_create_test_provider):
        """Test provider main page from left menu"""
        provider_config_page = ProviderConfigPage(
            app_fs.driver, app_fs.adcm.url, upload_and_create_test_provider.id
        ).open()
        provider_main_page = provider_config_page.open_main_tab()
        provider_main_page.wait_page_is_opened()
        provider_main_page.check_all_elements()

    @pytest.mark.smoke()
    def test_run_upgrade_on_provider_page_by_toolbar(self, app_fs, sdk_client_fs, upload_and_create_test_provider):
        """Test provider upgrade from toolbar"""
        params = {"state": "upgradated"}
        with allure.step("Create provider to export"):
            provider_export = sdk_client_fs.upload_from_fs(
                os.path.join(utils.get_data_dir(__file__), "upgradable_provider")
            )
            provider_export.provider_create("upgradable_provider")
        main_page = ProviderMainPage(app_fs.driver, app_fs.adcm.url, upload_and_create_test_provider.id).open()
        main_page.toolbar.run_upgrade(PROVIDER_NAME, PROVIDER_NAME)
        with allure.step("Check that provider has been upgraded"):
            provider_page = ProviderListPage(app_fs.driver, app_fs.adcm.url).open()
            row = provider_page.table.get_all_rows()[0]
            assert (
                provider_page.get_provider_info_from_row(row).state == params["state"]
            ), f"Provider state should be {params['state']}"


class TestProviderConfigPage:
    """Tests for provider config page"""

    @pytest.mark.smoke()
    def test_open_by_tab_provider_config_page(self, app_fs, upload_and_create_test_provider):
        """Test provider config page from left menu"""
        provider_main_page = ProviderMainPage(app_fs.driver, app_fs.adcm.url, upload_and_create_test_provider.id).open()
        provider_config_page = provider_main_page.open_config_tab()
        provider_config_page.wait_page_is_opened()
        provider_config_page.check_all_elements()

    @pytest.mark.smoke()
    def test_filter_config_on_provider_config_page(self, app_fs, upload_and_create_test_provider):
        """Test config filter on provider config page"""
        params = {"search_param": "str_param", "group_name": "core-site"}
        provider_config_page = ProviderConfigPage(
            app_fs.driver, app_fs.adcm.url, upload_and_create_test_provider.id
        ).open()
        with provider_config_page.config.wait_rows_change(expected_rows_amount=1):
            provider_config_page.config.search(params["search_param"])
        with allure.step(f"Check that rows are filtered by {params['search_param']}"):
            config_rows = provider_config_page.config.get_all_config_rows()
            assert (
                provider_config_page.config.get_config_row_info(config_rows[0]).name == f"{params['search_param']}:"
            ), f"Name should be {params['search_param']}"
        with provider_config_page.config.wait_rows_change():
            provider_config_page.config.clear_search_input()
        with allure.step("Check that rows are not filtered"):
            config_rows = provider_config_page.config.get_all_config_rows()
            assert len(config_rows) == 4, "Rows are filtered: there should be 4 row"
        with provider_config_page.config.wait_rows_change(expected_rows_amount=2):
            provider_config_page.config.click_on_group(params["group_name"])

    @pytest.mark.smoke()
    def test_save_custom_config_on_provider_config_page(self, app_fs, upload_and_create_test_provider):
        """Test save config on provider config page"""
        params = {
            "row_value_new": "test",
            "row_value_old": "0000",
            "config_name_new": "test_name",
            "config_name_old": "init",
        }
        provider_config_page = ProviderConfigPage(
            app_fs.driver, app_fs.adcm.url, upload_and_create_test_provider.id
        ).open()
        config_row = provider_config_page.config.get_all_config_rows()[0]
        provider_config_page.config.type_in_config_field(row=config_row, value=params["row_value_new"], clear=True)

        provider_config_page.config.set_description(params["config_name_new"])
        provider_config_page.config.save_config()
        provider_config_page.config.compare_versions(params["config_name_old"])
        with allure.step("Check row history"):
            row_with_history = provider_config_page.config.get_all_config_rows()[0]
            provider_config_page.config.wait_history_row_with_value(row_with_history, params["row_value_old"])

    def test_reset_config_in_row_on_provider_config_page(self, app_fs, upload_and_create_test_provider):
        """Test config reset on provider config page"""
        params = {
            "row_name": "str_param",
            "row_value_new": "test",
            "row_value_old": "0000",
            "config_name": "test_name",
        }
        provider_config_page = ProviderConfigPage(
            app_fs.driver, app_fs.adcm.url, upload_and_create_test_provider.id
        ).open()
        config_row = provider_config_page.config.get_all_config_rows()[0]
        provider_config_page.config.type_in_config_field(row=config_row, value=params["row_value_new"], clear=True)
        provider_config_page.config.set_description(params["config_name"])
        provider_config_page.config.save_config()

        provider_config_page.config.reset_to_default(row=config_row)
        provider_config_page.config.assert_input_value_is(
            expected_value=params["row_value_old"], display_name=params["row_name"]
        )

    @pytest.mark.parametrize("bundle", ["provider_required_fields"], indirect=True)
    def test_field_validation_on_provider_config_page(self, app_fs, bundle, upload_and_create_test_provider):
        """Test config field validation on provider config page"""
        params = {
            'pass_name': 'Test password',
            'req_name': 'Test Required item',
            'not_req_name': 'Test item',
            'wrong_value': 'test',
        }
        provider_config_page = ProviderConfigPage(
            app_fs.driver, app_fs.adcm.url, upload_and_create_test_provider.id
        ).open()
        provider_config_page.config.check_password_confirm_required(params['pass_name'])
        provider_config_page.config.check_field_is_required(params['req_name'])
        config_row = provider_config_page.config.get_all_config_rows()[0]
        provider_config_page.config.type_in_config_field(params['wrong_value'], row=config_row)
        provider_config_page.config.check_field_is_invalid(params['not_req_name'])
