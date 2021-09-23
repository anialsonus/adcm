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
from contextlib import contextmanager
from typing import (
    Optional,
    List,
    Union,
    Callable,
)

import allure
from adcm_pytest_plugin.utils import wait_until_step_succeeds
from selenium.common.exceptions import (
    NoSuchElementException,
    StaleElementReferenceException,
    TimeoutException,
)
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webdriver import WebElement
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait as WDW

from tests.ui_tests.app.helpers.locator import Locator
from tests.ui_tests.app.page.common.common_locators import CommonLocators
from tests.ui_tests.app.page.common.footer import CommonFooterLocators
from tests.ui_tests.app.page.common.header import (
    CommonHeaderLocators,
    AuthorizedHeaderLocators,
)
from tests.ui_tests.app.page.common.popups.locator import CommonPopupLocators
from tests.ui_tests.app.page.common.tooltip_links.locator import CommonToolbarLocators
from tests.ui_tests.utils import assert_enough_rows


class BasePageObject:
    """
    BasePageObject is parent class for all ADCM's pages.
    :param driver: Selenium WebDriver object, drives a browser
    :param base_url: string with page base url
    :param path_template: string template with path to a specific page. Template variables passed as kwargs
    :param header: header object, eg PageHeader
    :param footer: footer object, eg PageFooter
    :param default_page_timeout: default timeout for actions with page, eg open page or reload
    :param default_loc_timeout: default timeout for actions with locators, eg wait to display
    """

    __slots__ = {
        "driver",
        "base_url",
        "path",
        "header",
        "footer",
        "table",
        "default_page_timeout",
        "default_loc_timeout",
    }

    def __init__(
        self,
        driver: WebDriver,
        base_url: str,
        path_template: str = "",
        default_page_timeout: int = 10,
        default_loc_timeout: int = 15,
        **kwargs,
    ):
        if any(str.isdigit(char) for char in path_template):
            raise ValueError(
                f"Path template {path_template} should not contain any digits. "
                "Please use template string and pass values as kwargs"
            )
        self.driver = driver
        self.base_url = base_url
        self.path = path_template.format(**kwargs)
        self.default_page_timeout = default_page_timeout
        self.default_loc_timeout = default_loc_timeout
        allure.dynamic.label("page_url", path_template)

    def open(self, timeout: int = None):
        """Open page by its url and path."""

        url = self.base_url + self.path

        def open_page():
            if self.driver.current_url != url:
                with allure.step(f"Open {url}"):
                    self.driver.get(url)
                    assert self.path in self.driver.current_url, (
                        "Page URL didn't change. " f'Actual URL: {self.driver.current_url}. Expected URL: {url}.'
                    )

        wait_until_step_succeeds(open_page, period=0.5, timeout=timeout or self.default_page_timeout)
        return self

    @allure.step("Close popup at the bottom of the page")
    def close_info_popup(self):
        if self.is_element_displayed(CommonPopupLocators.block, timeout=5):
            self.find_and_click(CommonPopupLocators.hide_btn)
            self.wait_element_hide(CommonPopupLocators.block)

    @allure.step("Get text from info popup")
    def get_info_popup_text(self):
        self.wait_element_visible(CommonPopupLocators.block)
        return self.wait_element_visible(CommonPopupLocators.text, timeout=5).text

    @allure.step("Wait url to contain path {path}")
    def wait_url_contains_path(self, path: str, timeout: int = None) -> None:
        """Wait url to contain path."""

        url_timeout = timeout or self.default_page_timeout
        WDW(self.driver, url_timeout).until(
            EC.url_contains(path),
            message=f"Page with path '{path}' has not been " f"loaded for {url_timeout} seconds",
        )

    def find_element(self, locator: Locator, timeout: int = None) -> WebElement:
        """Find element on current page."""

        loc_timeout = timeout or self.default_loc_timeout
        with allure.step(f'Find element "{locator.name}" on page'):
            return WDW(self.driver, loc_timeout).until(
                EC.presence_of_element_located([locator.by, locator.value]),
                message=f"Can't find {locator.name} on page " f"{self.driver.current_url} for {loc_timeout} seconds",
            )

    def find_child(self, element: WebElement, child: Locator, timeout: int = None) -> WebElement:
        """Find child element on current page."""

        loc_timeout = timeout or self.default_loc_timeout
        with allure.step(f'Find element "{child.name}" on page'):
            return WDW(element, loc_timeout).until(
                EC.presence_of_element_located([child.by, child.value]),
                message=f"Can't find {child.name} on page " f"{self.driver.current_url} for {loc_timeout} seconds",
            )

    def find_children(self, element: WebElement, child: Locator, timeout: int = None) -> List[WebElement]:
        """Find children element on current page."""

        loc_timeout = timeout or self.default_loc_timeout
        with allure.step(f'Find element "{child.name}" on page'):
            return WDW(element, loc_timeout).until(
                EC.presence_of_all_elements_located([child.by, child.value]),
                message=f"Can't find {child.name} on page " f"{self.driver.current_url} for {loc_timeout} seconds",
            )

    def find_elements(self, locator: Locator, timeout: int = None) -> [WebElement]:
        """Find elements on current page."""

        loc_timeout = timeout or self.default_loc_timeout
        with allure.step(f'Find elements "{locator.name}" on page'):
            return WDW(self.driver, loc_timeout).until(
                EC.presence_of_all_elements_located([locator.by, locator.value]),
                message=f"Can't find {locator.name} on page " f"{self.driver.current_url} for {loc_timeout} seconds",
            )

    def is_element_displayed(self, element: Union[Locator, WebElement], timeout: int = None) -> bool:
        """Checks if element is displayed."""

        def find_element():
            return (
                element
                if isinstance(element, WebElement)
                else self.find_element(element, timeout=timeout or self.default_loc_timeout)
            )

        element_name = element.name if isinstance(element, Locator) else element.text
        return self._is_displayed(element_name, find_element)

    def is_child_displayed(self, parent: WebElement, child: Locator, timeout: Optional[int] = None) -> bool:
        """Checks if child element is displayed"""

        def find_child():
            return self.find_child(parent, child, timeout=timeout or self.default_loc_timeout)

        return self._is_displayed(child.name, find_child)

    def assert_displayed_elements(self, locators: List[Locator]) -> None:
        """Asserts that list of elements is displayed."""

        for loc in locators:
            assert self.is_element_displayed(
                loc
            ), f"Locator {loc.name} isn't displayed on page {self.driver.current_url}"

    def check_element_should_be_hidden(
        self, element: Union[Locator, WebElement], timeout: Optional[int] = None
    ) -> None:
        """Raises assertion error if element is still visible after timeout"""
        try:
            self.wait_element_hide(element, timeout)
        except TimeoutException as e:
            raise AssertionError(e.msg)

    def check_element_should_be_visible(self, locator: Locator, timeout: Optional[int] = None) -> None:
        """Raises assertion error if element is not visible after timeout"""
        try:
            self.wait_element_visible(locator, timeout)
        except TimeoutException as e:
            raise AssertionError(e.msg)

    def find_and_click(self, locator: Locator, is_js: bool = False) -> None:
        """Find element on current page and click on it."""

        if is_js:
            with allure.step(f'Click with js on "{locator.name}"'):
                loc = self.find_element(locator)
                self.driver.execute_script("arguments[0].click()", loc)
        else:
            with allure.step(f'Click on "{locator.name}"'):
                self.wait_element_clickable(locator)
                self.find_element(locator).click()

    def wait_element_clickable(self, locator: Locator, timeout: int = None) -> WebElement:
        """Wait for the element to become clickable."""

        loc_timeout = timeout or self.default_loc_timeout
        with allure.step(f'Wait "{locator.name}" clickable'):
            return WDW(self.driver, loc_timeout).until(
                EC.element_to_be_clickable([locator.by, locator.value]),
                message=f"locator {locator.name} hasn't become clickable for " f"{loc_timeout} seconds",
            )

    def wait_element_visible(self, locator: Locator, timeout: int = None) -> WebElement:
        """Wait for the element visibility."""

        loc_timeout = timeout or self.default_loc_timeout
        with allure.step(f'Wait "{locator.name}" presence'):
            return WDW(self.driver, loc_timeout).until(
                EC.visibility_of_element_located([locator.by, locator.value]),
                message=f"locator {locator.name} hasn't become visible for " f"{loc_timeout} seconds",
            )

    def wait_element_hide(self, element: Union[Locator, WebElement], timeout: int = None) -> None:
        """Wait the element to hide."""

        loc_timeout = timeout or self.default_loc_timeout
        el_name = element.name if isinstance(element, Locator) else element.text
        with allure.step(f'Check {el_name} to hide'):
            WDW(self.driver, loc_timeout).until(
                EC.invisibility_of_element_located(
                    [element.by, element.value] if isinstance(element, Locator) else element
                ),
                message=f"locator {el_name} hasn't hide for {loc_timeout} seconds",
            )

    def wait_element_attribute(
        self,
        locator: Locator,
        attribute: str,
        expected_value: str,
        exact_match: bool = True,
        timeout: int = 5,
    ):
        """
        Wait for element to has locator's attribute equals to `expected_value`
        If exact match is False then __contains__ is used
        """
        comparator = '__eq__' if exact_match else '__contains__'

        def assert_attribute_value():
            actual_value = self.find_element(locator).get_attribute(attribute)
            assert getattr(actual_value, comparator)(expected_value), (
                f'Attribute {attribute} of element "{locator}" '
                f'should be/has "{expected_value}", but "{actual_value}" was found'
            )

        wait_until_step_succeeds(assert_attribute_value, period=0.5, timeout=timeout)

    def wait_page_is_opened(self, timeout: int = None):
        """Wait for current page to be opened"""
        timeout = timeout or self.default_page_timeout

        def assert_page_is_opened():
            assert self.path in self.driver.current_url, f'Page is not opened at path {self.path} in {timeout}'

        page_name = self.__class__.__name__.replace('Page', '')
        with allure.step(f'Wait page {page_name} is opened'):
            wait_until_step_succeeds(assert_page_is_opened, period=0.5, timeout=timeout)
            self.wait_element_hide(CommonToolbarLocators.progress_bar)

    @allure.step('Write text to input element: "{text}"')
    def send_text_to_element(
        self, locator: Locator, text: str, clean_input: bool = True, timeout: Optional[int] = None
    ):
        """
        Writes text to input element found by locator

        If value of input before and after is the same, then retries to send keys again,
        because sometimes text doesn't appear in input

        :param locator: Locator of element to write into (should be input)
        :param text: Text to use in .send_keys method
        :param timeout: Timeout on finding element
        """
        element = self.find_element(locator, timeout)
        expected_value = element.get_property('value') + text

        def send_keys_and_check():
            if clean_input:
                self.clear_by_keys(locator)
            input_element = self.find_element(locator, timeout)
            input_element.send_keys(text)
            assert (
                actual_value := input_element.get_property('value')
            ) == expected_value, (
                f'Value of input {locator.name} expected to be "{expected_value}", but "{actual_value}" was found'
            )

        wait_until_step_succeeds(send_keys_and_check, period=0.5, timeout=1.5)

    @allure.step('Clear element')
    def clear_by_keys(self, locator: Locator) -> None:
        """Clears element value by keyboard."""

        def clear():
            element = self.find_element(locator)
            element.send_keys(Keys.CONTROL + "a")
            element.send_keys(Keys.BACK_SPACE)
            assert self.find_element(locator).text == ""

        wait_until_step_succeeds(clear, period=0.5, timeout=self.default_loc_timeout)

    @allure.step('Wait Config has been loaded after authentication')
    def wait_config_loaded(self):
        """
        Wait for hidden elements in DOM.
        Without this waiting and after the config finally is loaded
        there will be redirection to the greeting page.
        """

        self.find_element(CommonLocators.socket, timeout=30)
        self.find_element(CommonLocators.profile, timeout=30)

    def hover_element(self, element: Union[Locator, WebElement]):
        """
        Moves the cursor over an element and hovers it.
        """
        hover = ActionChains(self.driver).move_to_element(
            element if isinstance(element, WebElement) else self.find_element(element)
        )
        hover.perform()

    @staticmethod
    def _is_displayed(element_name: str, find_element_func: Callable[[], WebElement]) -> bool:
        """Calls `is_displayed` method on element returned by passed function"""
        try:
            with allure.step(f'Check {element_name}'):
                return find_element_func().is_displayed()
        except (
            TimeoutException,
            NoSuchElementException,
            StaleElementReferenceException,
            TimeoutError,
        ):
            return False

    @allure.step("Click back button in browser")
    def click_back_button_in_browser(self):
        self.driver.back()


class PageHeader(BasePageObject):
    """Class for header manipulating."""

    def __init__(self, driver, base_url):
        super().__init__(driver, base_url)

    @property
    def popup_jobs_row_count(self):
        return len(self.get_job_rows_from_popup())

    @allure.step('Check elements in header for authorized user')
    def check_auth_page_elements(self):
        self.assert_displayed_elements(
            [
                AuthorizedHeaderLocators.arenadata_logo,
                AuthorizedHeaderLocators.clusters,
                AuthorizedHeaderLocators.hostproviders,
                AuthorizedHeaderLocators.hosts,
                AuthorizedHeaderLocators.jobs,
                AuthorizedHeaderLocators.bundles,
                AuthorizedHeaderLocators.job_block,
                AuthorizedHeaderLocators.help_button,
                AuthorizedHeaderLocators.account_button,
            ]
        )

    @allure.step('Check elements in header for unauthorized user')
    def check_unauth_page_elements(self):
        self.wait_element_visible(CommonHeaderLocators.block)
        self.assert_displayed_elements(
            [
                CommonHeaderLocators.arenadata_logo,
                CommonHeaderLocators.clusters,
                CommonHeaderLocators.hostproviders,
                CommonHeaderLocators.hosts,
                CommonHeaderLocators.jobs,
                CommonHeaderLocators.bundles,
            ]
        )

    def click_arenadata_logo_in_header(self):
        self.find_and_click(CommonHeaderLocators.arenadata_logo)

    def click_cluster_tab_in_header(self):
        self.find_and_click(CommonHeaderLocators.clusters)

    def click_hostproviders_tab_in_header(self):
        self.find_and_click(CommonHeaderLocators.hostproviders)

    def click_hosts_tab_in_header(self):
        self.find_and_click(CommonHeaderLocators.hosts)

    def click_jobs_tab_in_header(self):
        self.find_and_click(CommonHeaderLocators.jobs)

    def click_bundles_tab_in_header(self):
        self.find_and_click(CommonHeaderLocators.bundles)

    def click_job_block_in_header(self):
        self.find_and_click(AuthorizedHeaderLocators.job_block)

    def click_help_button_in_header(self):
        self.find_and_click(AuthorizedHeaderLocators.help_button)

    def click_account_button_in_header(self):
        self.find_and_click(AuthorizedHeaderLocators.account_button)

    def check_job_popup(self):
        assert self.is_element_displayed(AuthorizedHeaderLocators.job_popup), 'Job popup should be displayed'

    def check_help_popup(self):
        self.wait_element_visible(AuthorizedHeaderLocators.block)
        self.assert_displayed_elements(
            [
                AuthorizedHeaderLocators.HelpPopup.ask_link,
                AuthorizedHeaderLocators.HelpPopup.doc_link,
            ]
        )

    def click_ask_link_in_help_popup(self):
        self.find_and_click(AuthorizedHeaderLocators.HelpPopup.ask_link)

    def click_doc_link_in_help_popup(self):
        self.find_and_click(AuthorizedHeaderLocators.HelpPopup.doc_link)

    def check_account_popup(self):
        self.wait_element_visible(AuthorizedHeaderLocators.block)
        acc_popup = AuthorizedHeaderLocators.AccountPopup
        self.assert_displayed_elements(
            [
                acc_popup.settings_link,
                acc_popup.profile_link,
                acc_popup.logout_button,
            ]
        )

    def click_settings_link_in_acc_popup(self):
        self.find_and_click(AuthorizedHeaderLocators.AccountPopup.settings_link)

    def click_profile_link_in_acc_popup(self):
        self.find_and_click(AuthorizedHeaderLocators.AccountPopup.profile_link)

    def click_logout_in_acc_popup(self):
        self.find_and_click(AuthorizedHeaderLocators.AccountPopup.logout_button)

    def get_success_job_amount_from_header(self):
        self.hover_element(AuthorizedHeaderLocators.job_block)
        self.wait_element_visible(AuthorizedHeaderLocators.job_popup)
        return self.find_element(AuthorizedHeaderLocators.JobPopup.success_jobs).text.split("\n")[1]

    def get_in_progress_job_amount_from_header(self):
        self.hover_element(AuthorizedHeaderLocators.job_block)
        self.wait_element_visible(AuthorizedHeaderLocators.job_popup)
        return self.find_element(AuthorizedHeaderLocators.JobPopup.in_progress_jobs).text.split("\n")[1]

    def get_failed_job_amount_from_header(self):
        self.hover_element(AuthorizedHeaderLocators.job_block)
        self.wait_element_visible(AuthorizedHeaderLocators.job_popup)
        return self.find_element(AuthorizedHeaderLocators.JobPopup.failed_jobs).text.split("\n")[1]

    def wait_success_job_amount_from_header(self, expected_job_amount: int):
        def wait_job():
            assert (
                int(self.get_success_job_amount_from_header()) == expected_job_amount
            ), f"Should be {expected_job_amount} tasks in popup header"

        wait_until_step_succeeds(wait_job, period=1, timeout=70)

    @allure.step('Open profile using account popup in header')
    def open_profile(self):
        """Open profile page"""
        self.click_account_button_in_header()
        self.click_profile_link_in_acc_popup()

    @allure.step('Logout using account popup in header')
    def logout(self):
        """Logout using account popup"""
        self.click_account_button_in_header()
        self.click_logout_in_acc_popup()

    @contextmanager
    def open_jobs_popup(self):
        """Open jobs popup by hovering icon and hover JOBS menu item afterwards"""
        self.hover_element(AuthorizedHeaderLocators.job_block)
        yield
        self.hover_element(AuthorizedHeaderLocators.jobs)

    def get_job_rows_from_popup(self) -> List[WebElement]:
        """Get job rows from *opened* popup"""
        self.wait_element_visible(AuthorizedHeaderLocators.job_popup)
        return self.find_elements(AuthorizedHeaderLocators.JobPopup.job_row)

    def click_on_task_row_by_name(self, task_name: str):
        for task in self.find_elements(AuthorizedHeaderLocators.JobPopup.job_row):
            name = self.find_child(task, AuthorizedHeaderLocators.JobPopup.JobRow.job_name)
            if name.text == task_name:
                name.click()
                return
        raise AssertionError(f"Task with name '{task_name}' not found")

    def get_single_job_row_from_popup(self, row_num: int = 0) -> WebElement:
        """Get single job row from *opened* popup"""

        def popup_table_has_enough_rows():
            assert_enough_rows(row_num, self.popup_jobs_row_count)

        with allure.step('Check popup table has enough rows'):
            wait_until_step_succeeds(popup_table_has_enough_rows, timeout=5, period=0.1)
        rows = self.get_job_rows_from_popup()
        assert_enough_rows(row_num, len(rows))
        return rows[row_num]

    def click_all_link_in_job_popup(self):
        self.wait_element_visible(AuthorizedHeaderLocators.JobPopup.block)
        self.find_and_click(AuthorizedHeaderLocators.JobPopup.show_all_link)

    def click_in_progress_in_job_popup(self):
        self.wait_element_visible(AuthorizedHeaderLocators.JobPopup.block)
        self.find_and_click(AuthorizedHeaderLocators.JobPopup.in_progress_jobs)

    def click_success_jobs_in_job_popup(self):
        self.wait_element_visible(AuthorizedHeaderLocators.JobPopup.block)
        self.find_and_click(AuthorizedHeaderLocators.JobPopup.success_jobs)

    def click_failed_jobs_in_job_popup(self):
        self.wait_element_visible(AuthorizedHeaderLocators.JobPopup.block)
        self.find_and_click(AuthorizedHeaderLocators.JobPopup.failed_jobs)

    def click_acknowledge_btn_in_job_popup(self):
        self.wait_element_visible(AuthorizedHeaderLocators.JobPopup.block)
        self.find_and_click(AuthorizedHeaderLocators.JobPopup.acknowledge_btn)

    def get_jobs_circle_color(self):
        return self.find_element(AuthorizedHeaderLocators.bell_icon).get_attribute("style")

    @allure.step("Check that job list is empty")
    def check_no_jobs_presented(self):
        if not self.is_element_displayed(AuthorizedHeaderLocators.JobPopup.block):
            self.find_and_click(AuthorizedHeaderLocators.jobs)
        assert (
            "Nothing to display" in self.find_element(AuthorizedHeaderLocators.JobPopup.empty_text).text
        ), "There should be message 'Nothing to display'"

    @allure.step("Check acknowledge button not displayed")
    def check_acknowledge_btn_not_displayed(self):
        if not self.is_element_displayed(AuthorizedHeaderLocators.JobPopup.block):
            self.find_and_click(AuthorizedHeaderLocators.jobs)
        assert not self.is_element_displayed(AuthorizedHeaderLocators.JobPopup.acknowledge_btn)


class PageFooter(BasePageObject):
    """Class for footer manipulating."""

    def __init__(self, driver, base_url):
        super().__init__(driver, base_url)

    @allure.step('Check elements in footer')
    def check_all_elements(self):
        self.assert_displayed_elements(
            [
                CommonFooterLocators.version_link,
                CommonFooterLocators.logo,
            ]
        )

    def click_version_link_in_footer(self):
        self.find_and_click(CommonFooterLocators.version_link)
