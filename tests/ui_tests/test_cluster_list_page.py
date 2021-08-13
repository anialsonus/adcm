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

import os

import allure
import pytest
from _pytest.fixtures import SubRequest
from adcm_client.objects import (
    ADCMClient,
    Bundle,
    Provider,
)
from adcm_pytest_plugin import utils

from tests.ui_tests.app.page.admin_intro.page import AdminIntroPage
from tests.ui_tests.app.page.cluster.page import (
    ClusterImportPage,
    ClusterConfigPage,
    ClusterMainPage,
    ClusterHostPage,
    ClusterServicesPage,
)
from tests.ui_tests.app.page.cluster_list.page import ClusterListPage
from tests.ui_tests.app.page.host.page import (
    HostMainPage,
    HostConfigPage,
)
from tests.ui_tests.app.page.service.page import (
    ServiceMainPage,
    ServiceConfigPage,
    ServiceImportPage,
)
from tests.ui_tests.test_host_page import check_host_info

BUNDLE_COMMUNITY = "cluster_community"
BUNDLE_ENTERPRISE = "cluster_enterprise"
BUNDLE_IMPORT = "cluster_to_import"
BUNDLE_UPGRADE = "upgradable_cluster"
BUNDLE_REQUIRED_FIELDS = "cluster_and_service_with_required_string"
BUNDLE_WITH_SERVICES = "cluster_with_services"
CLUSTER_NAME = "Test cluster"
SERVICE_NAME = "test_service"
PROVIDER_NAME = 'test_provider'
HOST_NAME = 'test-host'
PROVIDER_WITH_ISSUE_NAME = 'provider_with_issue'


# pylint: disable=redefined-outer-name


@pytest.fixture()
def create_community_cluster(sdk_client_fs: ADCMClient, app_fs):
    bundle = cluster_bundle(sdk_client_fs, BUNDLE_COMMUNITY)
    return bundle.cluster_create(name=CLUSTER_NAME)


@pytest.fixture()
def _create_community_cluster_with_service(sdk_client_fs: ADCMClient, app_fs):
    bundle = cluster_bundle(sdk_client_fs, BUNDLE_COMMUNITY)
    bundle.cluster_create(name=CLUSTER_NAME).service_add(name=SERVICE_NAME)


@pytest.fixture()
def _create_import_cluster_with_service(sdk_client_fs: ADCMClient, app_fs):
    params = {
        "import_cluster_name": "Import cluster",
        "import_service_name": "Pre-uploaded Dummy service to import",
    }
    with allure.step("Create main cluster"):
        bundle = cluster_bundle(sdk_client_fs, BUNDLE_COMMUNITY)
        bundle.cluster_create(name=CLUSTER_NAME).service_add(name=SERVICE_NAME)
    with allure.step("Create cluster to import"):
        bundle = cluster_bundle(sdk_client_fs, BUNDLE_IMPORT)
        bundle.cluster_create(name=params["import_cluster_name"]).service_add(
            name=params["import_service_name"]
        )


@allure.step("Upload cluster bundle")
def cluster_bundle(sdk_client_fs: ADCMClient, data_dir_name: str) -> Bundle:
    return sdk_client_fs.upload_from_fs(os.path.join(utils.get_data_dir(__file__), data_dir_name))


@pytest.fixture(params=["provider"])
@allure.title("Upload provider bundle")
def provider_bundle(request: SubRequest, sdk_client_fs: ADCMClient) -> Bundle:
    return sdk_client_fs.upload_from_fs(os.path.join(utils.get_data_dir(__file__), request.param))


@pytest.fixture()
@allure.title("Create provider")
def upload_and_create_provider(provider_bundle) -> Provider:
    return provider_bundle.provider_create(PROVIDER_NAME)


@pytest.fixture()
def _create_community_cluster_with_host(
    sdk_client_fs: ADCMClient, app_fs, upload_and_create_provider
):
    provider = upload_and_create_provider
    host = provider.host_create(fqdn=HOST_NAME)
    bundle = cluster_bundle(sdk_client_fs, BUNDLE_COMMUNITY)
    bundle.cluster_create(name=CLUSTER_NAME).host_add(host)


@pytest.fixture()
@allure.title("Create host")
def _create_host(upload_and_create_provider):
    """Create default host using API"""
    provider = upload_and_create_provider
    provider.host_create(HOST_NAME)


@pytest.mark.parametrize(
    "bundle_archive",
    [
        pytest.param(utils.get_data_dir(__file__, BUNDLE_COMMUNITY), id="community"),
        pytest.param(utils.get_data_dir(__file__, BUNDLE_ENTERPRISE), id="enterprise"),
    ],
    indirect=True,
)
def test_check_cluster_list_page_with_cluster_creating(
    app_fs, login_to_adcm_over_api, bundle_archive
):
    edition = bundle_archive.split("cluster_")[2][:-4]
    cluster_params = {
        "bundle": f"test_cluster 1.5 {edition}",
        "description": "Test",
        "state": "created",
    }
    cluster_page = ClusterListPage(app_fs.driver, app_fs.adcm.url).open()
    with allure.step("Check no cluster rows"):
        assert len(cluster_page.table.get_all_rows()) == 0, "There should be no row with clusters"
    cluster_page.create_cluster(
        bundle_archive, cluster_params['description'], is_license=bool(edition == "enterprise")
    )
    with allure.step("Check uploaded cluster"):
        assert len(cluster_page.table.get_all_rows()) == 1, "There should be 1 row with cluster"
        uploaded_cluster = cluster_page.get_cluster_info_from_row(0)
        assert cluster_params['bundle'] == uploaded_cluster['bundle'], (
            f"Cluster bundle should be {cluster_params['bundle']} and "
            f"not {uploaded_cluster['bundle']}"
        )
        assert cluster_params['description'] == uploaded_cluster['description'], (
            f"Cluster description should be {cluster_params['description']} and "
            f"not {uploaded_cluster['description']}"
        )
        assert (
            cluster_params['state'] == uploaded_cluster['state']
        ), f"Cluster state should be {cluster_params['state']} and not {uploaded_cluster['state']}"


def test_check_cluster_list_page_pagination(
    sdk_client_fs: ADCMClient, app_fs, login_to_adcm_over_api
):
    with allure.step("Create 11 clusters"):
        bundle = cluster_bundle(sdk_client_fs, BUNDLE_COMMUNITY)
        for i in range(11):
            bundle.cluster_create(name=f"Test cluster {i}")
    cluster_page = ClusterListPage(app_fs.driver, app_fs.adcm.url).open()
    cluster_page.close_info_popup()
    cluster_page.table.check_pagination(second_page_item_amount=1)


@pytest.mark.usefixtures("create_community_cluster")
def test_check_cluster_list_page_action_run(app_fs, login_to_adcm_over_api):
    params = {"action_name": "test_action", "expected_state": "installed"}
    cluster_page = ClusterListPage(app_fs.driver, app_fs.adcm.url).open()
    row = cluster_page.table.get_all_rows()[0]
    with cluster_page.wait_cluster_state_change(row):
        cluster_page.run_action_in_cluster_row(row, params["action_name"])
    with allure.step("Check cluster state has changed"):
        assert (
            cluster_page.get_cluster_state_from_row(row) == params["expected_state"]
        ), f"Cluster state should be {params['expected_state']}"
    with allure.step("Check success cluster job"):
        assert (
            cluster_page.header.get_success_job_amount_from_header() == "1"
        ), "There should be 1 success cluster job in header"


@pytest.mark.usefixtures("_create_import_cluster_with_service")
def test_check_cluster_list_page_import_run(
    sdk_client_fs: ADCMClient, app_fs, login_to_adcm_over_api
):
    cluster_page = ClusterListPage(app_fs.driver, app_fs.adcm.url).open()
    row = cluster_page.get_row_by_cluster_name(CLUSTER_NAME)
    cluster_page.click_import_btn_in_row(row)
    import_page = ClusterImportPage(app_fs.driver, app_fs.adcm.url, 1)
    import_page.wait_page_is_opened()
    with allure.step("Check import on import page"):
        assert (
            len(import_page.get_import_items()) == 1
        ), "Cluster import page should contain 1 import"


@pytest.mark.usefixtures("create_community_cluster")
def test_check_cluster_list_page_open_cluster_config(app_fs, login_to_adcm_over_api):
    cluster_page = ClusterListPage(app_fs.driver, app_fs.adcm.url).open()
    row = cluster_page.table.get_all_rows()[0]
    cluster_page.click_config_button_in_row(row)
    ClusterConfigPage(app_fs.driver, app_fs.adcm.url, 1).wait_page_is_opened()


@pytest.mark.usefixtures("create_community_cluster")
def test_check_cluster_list_page_open_cluster_main(app_fs, login_to_adcm_over_api):
    cluster_page = ClusterListPage(app_fs.driver, app_fs.adcm.url).open()
    row = cluster_page.table.get_all_rows()[0]
    cluster_page.click_cluster_name_in_row(row)
    ClusterMainPage(app_fs.driver, app_fs.adcm.url, 1).wait_page_is_opened()


@pytest.mark.usefixtures("create_community_cluster")
def test_check_cluster_list_page_delete_cluster(app_fs, login_to_adcm_over_api):
    cluster_page = ClusterListPage(app_fs.driver, app_fs.adcm.url).open()
    row = cluster_page.table.get_all_rows()[0]
    with cluster_page.table.wait_rows_change():
        cluster_page.delete_cluster_by_row(row)
    with allure.step("Check there are no rows"):
        assert len(cluster_page.table.get_all_rows()) == 0, "Cluster table should be empty"


@pytest.mark.usefixtures("create_community_cluster")
def test_check_cluster_main_page_open_by_tab(app_fs, login_to_adcm_over_api):
    cluster_config_page = ClusterConfigPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_config_page.open_main_tab()
    cluster_main_page = ClusterMainPage(app_fs.driver, app_fs.adcm.url, 1)
    cluster_main_page.wait_page_is_opened()
    cluster_main_page.check_all_elements()


@pytest.mark.usefixtures("create_community_cluster")
def test_check_cluster_admin_page_open_by_toolbar(app_fs, login_to_adcm_over_api):
    cluster_main_page = ClusterMainPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_main_page.toolbar.click_admin_link()
    AdminIntroPage(app_fs.driver, app_fs.adcm.url).wait_page_is_opened()


@pytest.mark.usefixtures("create_community_cluster")
def test_check_cluster_main_page_open_by_toolbar(app_fs, login_to_adcm_over_api):
    params = {"cluster_list_name": "CLUSTERS"}
    cluster_main_page = ClusterMainPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_main_page.toolbar.click_link_by_name(params["cluster_list_name"])
    ClusterListPage(app_fs.driver, app_fs.adcm.url).wait_page_is_opened()
    cluster_import_page = ClusterImportPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_import_page.toolbar.click_link_by_name(CLUSTER_NAME)
    cluster_main_page.wait_page_is_opened()


def test_check_cluster_run_upgrade_on_cluster_page_by_toolbar(
    sdk_client_fs, app_fs, login_to_adcm_over_api
):
    params = {
        "upgrade_cluster_name": "upgrade cluster",
        "upgrade": "upgrade 2",
        "state": "upgradated",
    }
    with allure.step("Create main cluster"):
        bundle = cluster_bundle(sdk_client_fs, BUNDLE_COMMUNITY)
        bundle.cluster_create(name=CLUSTER_NAME)
    with allure.step("Create cluster to upgrade"):
        bundle = cluster_bundle(sdk_client_fs, BUNDLE_UPGRADE)
        bundle.cluster_create(name=params["upgrade_cluster_name"])
    main_page = ClusterMainPage(app_fs.driver, app_fs.adcm.url, 2).open()
    main_page.toolbar.run_upgrade(params["upgrade_cluster_name"], params["upgrade"])
    with allure.step("Check that cluster has been upgraded"):
        cluster_page = ClusterListPage(app_fs.driver, app_fs.adcm.url).open()
        row = cluster_page.get_row_by_cluster_name(params["upgrade_cluster_name"])
        assert (
            cluster_page.get_cluster_state_from_row(row) == params["state"]
        ), f"Cluster state should be {params['state']}"


@pytest.mark.usefixtures("create_community_cluster")
def test_check_cluster_run_action_on_cluster_page_by_toolbar(app_fs, login_to_adcm_over_api):
    params = {"action_name": "test_action"}
    cluster_main_page = ClusterMainPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_main_page.toolbar.run_action(CLUSTER_NAME, params["action_name"])
    with allure.step("Check success job"):
        assert (
            cluster_main_page.header.get_in_progress_job_amount_from_header() == "1"
        ), "There should be 1 in progress job in header"


@pytest.mark.usefixtures("create_community_cluster")
def test_check_cluster_service_page_open_by_tab(app_fs, login_to_adcm_over_api):
    cluster_config_page = ClusterConfigPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_config_page.open_services_tab()
    cluster_service_page = ClusterServicesPage(app_fs.driver, app_fs.adcm.url, 1)
    cluster_service_page.wait_page_is_opened()
    cluster_service_page.check_all_elements()


@pytest.mark.usefixtures("create_community_cluster")
def test_check_create_and_open_service_page_from_cluster_page(app_fs, login_to_adcm_over_api):
    params = {"service_name": "test_service - 1.2"}
    cluster_service_page = ClusterServicesPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_service_page.add_service_by_name(params["service_name"])
    service_row = cluster_service_page.table.get_all_rows()[0]
    service_row.click()
    ServiceMainPage(app_fs.driver, app_fs.adcm.url, 1, 1).wait_page_is_opened()


def test_check_required_fields_from_cluster_list_page(
    sdk_client_fs: ADCMClient, app_fs, login_to_adcm_over_api
):
    params = {"issue_name": "Configuration"}
    bundle = cluster_bundle(sdk_client_fs, BUNDLE_REQUIRED_FIELDS)
    bundle.cluster_create(name=CLUSTER_NAME)
    cluster_list_page = ClusterListPage(app_fs.driver, app_fs.adcm.url).open()
    row = cluster_list_page.table.get_all_rows()[0]
    cluster_list_page.click_on_issue_by_name(row, params["issue_name"])
    ClusterConfigPage(app_fs.driver, app_fs.adcm.url, 1).wait_page_is_opened()


def test_check_required_fields_from_service_list_page(
    sdk_client_fs: ADCMClient, app_fs, login_to_adcm_over_api
):
    params = {"service_name": "test_service", "issue_name": "Configuration"}
    bundle = cluster_bundle(sdk_client_fs, BUNDLE_REQUIRED_FIELDS)
    bundle.cluster_create(name=CLUSTER_NAME).service_add(name=params["service_name"])
    cluster_service_page = ClusterServicesPage(app_fs.driver, app_fs.adcm.url, 1).open()
    row = cluster_service_page.table.get_all_rows()[0]
    cluster_service_page.click_on_issue_by_name(row, params["issue_name"])
    ServiceConfigPage(app_fs.driver, app_fs.adcm.url, 1, 1).wait_page_is_opened()


@pytest.mark.usefixtures("_create_community_cluster_with_service")
def test_check_actions_from_service_list_page(app_fs, login_to_adcm_over_api):
    params = {"action_name": "test_action", "expected_state": "installed"}
    cluster_service_page = ClusterServicesPage(app_fs.driver, app_fs.adcm.url, 1).open()
    row = cluster_service_page.table.get_all_rows()[0]
    with cluster_service_page.wait_service_state_change(row):
        cluster_service_page.run_action_in_service_row(row, params["action_name"])
    with allure.step("Check service state has changed"):
        assert (
            cluster_service_page.get_service_state_from_row(row) == params["expected_state"]
        ), f"Cluster state should be {params['expected_state']}"
    with allure.step("Check success service job"):
        assert (
            cluster_service_page.header.get_success_job_amount_from_header() == "1"
        ), "There should be 1 success service job in header"


@pytest.mark.usefixtures("_create_import_cluster_with_service")
def test_check_service_list_page_import_run(app_fs, login_to_adcm_over_api):
    cluster_service_page = ClusterServicesPage(app_fs.driver, app_fs.adcm.url, 1).open()
    row = cluster_service_page.table.get_all_rows()[0]
    cluster_service_page.click_import_btn_in_row(row)
    import_page = ServiceImportPage(app_fs.driver, app_fs.adcm.url, 1, 1)
    import_page.wait_page_is_opened()
    with allure.step("Check import on import page"):
        assert (
            len(import_page.get_import_items()) == 1
        ), "Service import page should contain 1 import"


@pytest.mark.usefixtures("_create_community_cluster_with_service")
def test_check_service_list_page_open_service_config(app_fs, login_to_adcm_over_api):
    cluster_service_page = ClusterServicesPage(app_fs.driver, app_fs.adcm.url, 1).open()
    row = cluster_service_page.table.get_all_rows()[0]
    cluster_service_page.click_config_btn_in_row(row)
    ServiceConfigPage(app_fs.driver, app_fs.adcm.url, 1, 1).wait_page_is_opened()


def test_check_pagination_on_service_list_page(
    sdk_client_fs: ADCMClient, app_fs, login_to_adcm_over_api
):
    bundle = cluster_bundle(sdk_client_fs, BUNDLE_WITH_SERVICES)
    bundle.cluster_create(name=CLUSTER_NAME)
    cluster_service_page = ClusterServicesPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_service_page.add_service_by_name(service_name="All")
    cluster_service_page.table.check_pagination(second_page_item_amount=2)


@pytest.mark.usefixtures("_create_community_cluster_with_service")
def test_check_required_fields_from_cluster_host_page(app_fs, login_to_adcm_over_api):
    cluster_main_page = ClusterMainPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_main_page.open_hosts_tab()
    cluster_host_page = ClusterHostPage(app_fs.driver, app_fs.adcm.url, 1)
    cluster_host_page.wait_page_is_opened()
    cluster_host_page.check_all_elements()


@pytest.mark.parametrize(
    "bundle_archive", [utils.get_data_dir(__file__, "provider")], indirect=True
)
@pytest.mark.usefixtures("_create_community_cluster_with_service")
def test_check_create_host_and_hostprovider_from_cluster_host_page(
    app_fs, login_to_adcm_over_api, bundle_archive: str
):
    cluster_host_page = ClusterHostPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_host_page.wait_page_is_opened()
    cluster_host_page.click_add_host_btn(is_not_first_host=False)
    new_provider_name = cluster_host_page.host_popup.create_provider_and_host(
        bundle_archive, HOST_NAME
    )
    host_info = cluster_host_page.get_host_info_from_row(table_has_cluster_column=False)
    check_host_info(host_info, HOST_NAME, new_provider_name, None, 'created')


@pytest.mark.usefixtures("_create_community_cluster_with_service")
@pytest.mark.usefixtures("upload_and_create_provider")
def test_check_create_host_from_cluster_host_page(app_fs, login_to_adcm_over_api):
    cluster_host_page = ClusterHostPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_host_page.wait_page_is_opened()
    cluster_host_page.click_add_host_btn(is_not_first_host=False)
    cluster_host_page.host_popup.create_host(HOST_NAME)
    host_info = cluster_host_page.get_host_info_from_row(table_has_cluster_column=False)
    check_host_info(host_info, HOST_NAME, PROVIDER_NAME, None, 'created')
    host_row = cluster_host_page.table.get_all_rows()[0]
    cluster_host_page.click_on_host_name_in_host_row(host_row)
    HostMainPage(app_fs.driver, app_fs.adcm.url, 1, 1).wait_page_is_opened()


@pytest.mark.usefixtures("_create_community_cluster_with_service")
@pytest.mark.usefixtures('_create_host')
def test_check_create_host_error_from_cluster_host_page(app_fs, login_to_adcm_over_api):
    cluster_host_page = ClusterHostPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_host_page.wait_page_is_opened()
    cluster_host_page.close_info_popup()
    cluster_host_page.click_add_host_btn()
    cluster_host_page.host_popup.create_host(HOST_NAME)
    with allure.step("Check error message"):
        assert (
            cluster_host_page.get_info_popup_text()
            == '[ CONFLICT ] HOST_CONFLICT -- duplicate host'
        ), "No message about host duplication"


@pytest.mark.parametrize('provider_bundle', [PROVIDER_WITH_ISSUE_NAME], indirect=True)
@pytest.mark.usefixtures("_create_community_cluster_with_host")
def test_check_open_host_issue_from_cluster_host_page(
    app_fs, login_to_adcm_over_api, provider_bundle
):
    params = {"issue_name": "Configuration"}
    cluster_host_page = ClusterHostPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_host_page.wait_page_is_opened()
    row = cluster_host_page.table.get_all_rows()[0]
    cluster_host_page.click_on_issue_by_name(row, params["issue_name"])
    HostConfigPage(app_fs.driver, app_fs.adcm.url, 1, 1).wait_page_is_opened()


@pytest.mark.usefixtures("_create_community_cluster_with_host")
def test_check_host_action_run_from_cluster(app_fs, login_to_adcm_over_api):
    params = {"action_name": "test_action", "expected_state": "installed"}
    cluster_host_page = ClusterHostPage(app_fs.driver, app_fs.adcm.url, 1).open()
    row = cluster_host_page.table.get_all_rows()[0]
    with cluster_host_page.wait_host_state_change(row):
        cluster_host_page.run_action_in_host_row(row, params["action_name"])
    with allure.step("Check host state has changed"):
        assert (
            cluster_host_page.get_host_state_from_row(row) == params["expected_state"]
        ), f"Cluster state should be {params['expected_state']}"
    with allure.step("Check success host job"):
        assert (
            cluster_host_page.header.get_success_job_amount_from_header() == "1"
        ), "There should be 1 success host job in header"


@pytest.mark.usefixtures("_create_community_cluster_with_host")
def test_check_delete_host_from_cluster_host_page(app_fs, login_to_adcm_over_api):
    cluster_host_page = ClusterHostPage(app_fs.driver, app_fs.adcm.url, 1).open()
    row = cluster_host_page.table.get_all_rows()[0]
    with cluster_host_page.table.wait_rows_change():
        cluster_host_page.delete_host_by_row(row)
    with allure.step("Check there are no rows"):
        assert len(cluster_host_page.table.get_all_rows()) == 0, "Host table should be empty"


@pytest.mark.usefixtures("_create_community_cluster_with_host")
def test_open_host_config_from_cluster_host_page(app_fs, login_to_adcm_over_api):
    cluster_host_page = ClusterHostPage(app_fs.driver, app_fs.adcm.url, 1).open()
    row = cluster_host_page.table.get_all_rows()[0]
    cluster_host_page.click_config_btn_in_row(row)
    HostConfigPage(app_fs.driver, app_fs.adcm.url, 1, 1).wait_page_is_opened()


def test_check_pagination_on_cluster_host_page(
    app_fs, login_to_adcm_over_api, upload_and_create_provider, create_community_cluster
):
    cluster = create_community_cluster
    provider = upload_and_create_provider
    for i in range(11):
        host = provider.host_create(f"{HOST_NAME}_{i}")
        cluster.host_add(host)
    cluster_host_page = ClusterHostPage(app_fs.driver, app_fs.adcm.url, 1).open()
    cluster_host_page.table.check_pagination(1)
