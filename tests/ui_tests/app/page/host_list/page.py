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
from dataclasses import dataclass
from typing import Optional

import allure
from adcm_pytest_plugin.utils import wait_until_step_succeeds
from selenium.webdriver.remote.webelement import WebElement

from tests.ui_tests.app.helpers.locator import Locator
from tests.ui_tests.app.page.common.base_page import (
    BasePageObject,
    PageHeader,
    PageFooter,
)
from tests.ui_tests.app.page.common.dialogs import DeleteDialog, ActionDialog
from tests.ui_tests.app.page.common.popups.locator import HostCreationLocators
from tests.ui_tests.app.page.common.popups.page import HostCreatePopupObj
from tests.ui_tests.app.page.common.table.page import CommonTableObj
from tests.ui_tests.app.page.host_list.locators import HostListLocators


@dataclass
class HostRowInfo:
    """Information from host row about host"""

    # helper to check if any cluster is assigned
    UNASSIGNED_CLUSTER_VALUE = 'Assign to cluster'
    fqdn: str
    provider: str
    cluster: Optional[str]
    state: str


class HostListPage(BasePageObject):
    def __init__(self, driver, base_url):
        super().__init__(driver, base_url, "/host")
        self.header = PageHeader(self.driver, self.base_url)
        self.footer = PageFooter(self.driver, self.base_url)
        self.table = CommonTableObj(self.driver, self.base_url, HostListLocators.HostTable)
        self.host_popup = HostCreatePopupObj(self.driver, self.base_url)

    def get_host_row(self, row_num: int = 0) -> WebElement:
        def table_has_enough_rows():
            self.__assert_enough_rows(row_num, self.table.row_count)

        wait_until_step_succeeds(table_has_enough_rows, timeout=5, period=0.1)
        rows = self.table.get_all_rows()
        self.__assert_enough_rows(row_num, len(rows))
        return rows[row_num]

    def get_host_info_from_row(self, row_num: int = 0) -> HostRowInfo:
        row = self.get_host_row(row_num)
        row_elements = HostListLocators.HostTable.HostRow
        cluster_value = self.find_child(row, row_elements.cluster).text
        return HostRowInfo(
            fqdn=self.find_child(row, row_elements.fqdn).text,
            provider=self.find_child(row, row_elements.provider).text,
            cluster=cluster_value
            if cluster_value != HostRowInfo.UNASSIGNED_CLUSTER_VALUE
            else None,
            state=self.find_child(row, row_elements.state).text,
        )

    def click_on_row_child(self, row_num: int, child_locator: Locator):
        row = self.get_host_row(row_num)
        self.find_child(row, child_locator).click()

    @allure.step('Run action "{action_display_name}" on host in row {host_row_num}')
    def run_action(self, host_row_num: int, action_display_name: str):
        host_row = HostListLocators.HostTable.HostRow
        self.click_on_row_child(host_row_num, host_row.actions)
        init_action = self.wait_element_visible(host_row.action_option(action_display_name))
        init_action.click()
        self.wait_element_visible(ActionDialog.body)
        self.find_and_click(ActionDialog.run)

    @allure.step('Delete host in row {host_row_num}')
    def delete_host(self, host_row_num: int):
        """Delete host from table row"""
        self.click_on_row_child(host_row_num, HostListLocators.HostTable.HostRow.delete_btn)
        self.wait_element_visible(DeleteDialog.body)
        self.find_and_click(DeleteDialog.yes)
        self.wait_element_hide(DeleteDialog.body)

    @allure.step('Bind host in row {host_row_num} to cluster "{cluster_name}"')
    def bind_host_to_cluster(self, host_row_num: int, cluster_name: str):
        """Assign host to cluster in host list table"""
        self.click_on_row_child(host_row_num, HostListLocators.HostTable.HostRow.cluster)
        self.host_popup.wait_and_click_on_cluster_option(
            cluster_name, HostListLocators.HostTable.cluster_option
        )

    @allure.step('Assert host in row {row_num} is assigned to cluster {cluster_name}')
    def assert_host_bonded_to_cluster(self, row_num: int, cluster_name: str):
        def check_host_cluster(page: HostListPage, row: WebElement):
            real_cluster = page.find_child(row, HostListLocators.HostTable.HostRow.cluster).text
            assert real_cluster == cluster_name

        host_row = self.get_host_row(row_num)
        wait_until_step_succeeds(check_host_cluster, timeout=5, period=0.1, page=self, row=host_row)

    @allure.step('Assert host in row {row_num} has state "{state}"')
    def assert_host_state(self, row_num: int, state: str):
        def check_host_state(page: HostListPage, row: WebElement):
            real_state = page.find_child(row, HostListLocators.HostTable.HostRow.state).text
            assert real_state == state

        host_row = self.get_host_row(row_num)
        wait_until_step_succeeds(check_host_state, timeout=10, period=0.5, page=self, row=host_row)

    def open_host_creation_popup(self):
        self.find_and_click(HostListLocators.Tooltip.host_add_btn)
        self.wait_element_visible(HostCreationLocators.block)

    @staticmethod
    def __assert_enough_rows(required_row_num: int, row_count: int):
        """
        Assert that row "is presented" by comparing row index and amount of rows
        Provide row as index (starting with 0)
        """
        assert (
            required_row_num + 1 <= row_count
        ), f"Host table has only {row_count} rows when row #{required_row_num} was requested"
