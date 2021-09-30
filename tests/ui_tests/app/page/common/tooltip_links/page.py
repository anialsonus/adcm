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

"""Tooltip page PageObjects classes"""

import allure

from tests.ui_tests.app.page.common.base_page import BasePageObject
from tests.ui_tests.app.page.common.dialogs_locators import (
    ActionDialog,
)
from tests.ui_tests.app.page.common.tooltip_links.locator import CommonToolbarLocators


class CommonToolbar(BasePageObject):
    """Common Toolbar class"""

    def __init__(self, driver, base_url):
        super().__init__(driver, base_url)

    @allure.step("Click on admin link")
    def click_admin_link(self):
        """Click on admin link"""
        self.wait_element_hide(CommonToolbarLocators.progress_bar)
        self.wait_element_visible(CommonToolbarLocators.admin_link).click()

    @allure.step("Click on link {link_name}")
    def click_link_by_name(self, link_name: str):
        """Click on link by name"""
        self.wait_element_hide(CommonToolbarLocators.progress_bar)
        self.wait_element_visible(CommonToolbarLocators.admin_link)
        self.find_and_click(CommonToolbarLocators.text_link(link_name.upper().strip("_")))

    @allure.step("Run action {action_name} in {tab_name}")
    def run_action(self, tab_name: str, action_name: str):
        """Run Action from toolbar"""
        self.wait_element_visible(CommonToolbarLocators.admin_link)
        self.find_and_click(CommonToolbarLocators.action_btn(tab_name.upper().strip("_")))
        self.wait_element_visible(CommonToolbarLocators.Popup.popup_block)
        self.find_and_click(CommonToolbarLocators.Popup.item(action_name))
        self.wait_element_visible(ActionDialog.body)
        self.find_and_click(ActionDialog.run)

    @allure.step("Run upgrade {upgrade_name} in {tab_name}")
    def run_upgrade(self, tab_name: str, upgrade_name: str):
        """Run Upgrade from toolbar"""
        self.wait_element_visible(CommonToolbarLocators.admin_link)
        self.find_and_click(CommonToolbarLocators.upgrade_btn(tab_name.upper().strip("_")))
        self.wait_element_visible(CommonToolbarLocators.Popup.popup_block)
        self.find_and_click(CommonToolbarLocators.Popup.item(upgrade_name))
        self.wait_element_visible(ActionDialog.body)
        self.find_and_click(ActionDialog.run)
