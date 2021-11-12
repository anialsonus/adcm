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

"""Cluster page locators"""

from selenium.webdriver.common.by import By

from tests.ui_tests.app.helpers.locator import (
    Locator,
)
from tests.ui_tests.app.page.host_list.locators import HostListLocators


class ClusterMainLocators:
    """Cluster main page elements locators"""

    text = Locator(By.CSS_SELECTOR, ".mat-card-content", "Cluster main page text")


class ClusterServicesLocators:
    """Cluster main page elements locators"""

    add_services_btn = Locator(By.CSS_SELECTOR, "button[adcm_test='create-btn']", "Add services button")
    service_row = Locator(By.CSS_SELECTOR, ".mat-row", "Service row")

    class AddServicePopup:
        """Popup for adding services"""

        block = Locator(By.CSS_SELECTOR, ".mat-dialog-container", "Popup block")
        service_row = Locator(By.CSS_SELECTOR, ".mat-list-option", "Service row")
        create_btn = Locator(By.CSS_SELECTOR, "app-add-service button:last-child", "Add button")
        cancel_btn = Locator(By.CSS_SELECTOR, "app-add-service button:first-child", "Cancel button")

        class ServiceRow:
            """Locators for services row"""

            text = Locator(By.CSS_SELECTOR, ".mat-list-text", "Service name")

    class ServiceTableRow:
        """Services table roe locators"""

        name = Locator(By.CSS_SELECTOR, "mat-cell:first-of-type", "Service name")
        version = Locator(By.CSS_SELECTOR, "mat-cell:nth-child(2)", "Service version")
        state = Locator(By.CSS_SELECTOR, "app-state-column", "Service state")
        status = Locator(By.CSS_SELECTOR, "app-status-column button", "Service status")
        actions = Locator(By.CSS_SELECTOR, "app-actions-button button", "Service actions")
        service_import = Locator(By.CSS_SELECTOR, "mat-cell:nth-child(6) button", "Service import")
        config = Locator(By.CSS_SELECTOR, "mat-cell:nth-child(7) button", "Service config")


class ClusterHostLocators:
    """Cluster host page elements locators"""

    add_host_btn = Locator(By.CSS_SELECTOR, "button[adcm_test='create-btn']", "Add host button")

    class HostTable(HostListLocators.HostTable):
        """Cluster host page host table elements locators"""

        ...


class ClusterComponentsLocators:
    """Cluster components page elements locators"""

    restore_btn = Locator(By.XPATH, "//button[./span[contains(text(), 'Restore')]]", "Restore button")
    save_btn = Locator(By.XPATH, "//button[./span[contains(text(), 'Save')]]", "Save button")

    components_title = Locator(By.XPATH, "//h3[./span[contains(text(), 'Components')]]", "Title for Components block")
    service_page_link = Locator(By.CSS_SELECTOR, "mat-card-content a[href*='service']", "Link to service page")

    hosts_title = Locator(By.XPATH, "//h3[./span[contains(text(), 'Hosts')]]", "Title for Hosts block")
    hosts_page_link = Locator(By.CSS_SELECTOR, "mat-card-content a[href*='host']", "Link to hosts page")
    create_hosts_btn = Locator(By.CSS_SELECTOR, "button[adcm_test='create-btn']", "Create hosts button")

    host_row = Locator(By.XPATH, "//div[./h3/span[contains(text(), 'Host')]]//app-much-2-many", "Host row")
    component_row = Locator(
        By.XPATH,
        "//div[./h3/span[contains(text(), 'Components')]]//app-much-2-many",
        "Component row",
    )

    class Row:
        """Cluster components page row elements locators"""

        name = Locator(By.XPATH, ".//button[@mat-button]/span/span[not(contains(@class, 'warn'))]", "Item name")
        number = Locator(By.CSS_SELECTOR, "button[mat-raised-button] span:first-of-type", "Amount of links")
        relations_row = Locator(By.CSS_SELECTOR, "div[class*='relations-list']", "Row with relations")

        class RelationsRow:
            """Cluster components page relations row elements locators"""

            name = Locator(By.CSS_SELECTOR, "div>span", "Related item name")
            delete_btn = Locator(By.CSS_SELECTOR, "button", "Delete item button")


class ClusterActionLocators:
    """Cluster action page elements locators"""

    action_card = Locator(By.CSS_SELECTOR, "app-action-card", "Action card")
    info_text = Locator(By.CSS_SELECTOR, "app-action-card p", "Text on action page")

    class ActionCard:
        """Cluster action page action card elements locators"""

        play_btn = Locator(By.CSS_SELECTOR, "button", "Action run button")
