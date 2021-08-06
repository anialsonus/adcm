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
from typing import TypedDict, TypeVar, Union

import allure

from enum import Enum
from selenium.webdriver.remote.webelement import WebElement

from tests.ui_tests.app.helpers.locator import Locator
from tests.ui_tests.app.page.common.base_page import (
    BasePageObject,
    PageHeader,
    PageFooter,
)
from tests.ui_tests.app.page.common.header import AuthorizedHeaderLocators
from tests.ui_tests.app.page.common.table.page import CommonTableObj
from tests.ui_tests.app.page.common.tooltip_links.locator import CommonToolbarLocators
from tests.ui_tests.app.page.job_list.locators import TaskListLocators


class JobStatus(Enum):
    RUNNING = 'running'
    SUCCESS = 'success'
    FAILED = 'failed'


class PopupJobInfo(TypedDict):
    """Info about the job from popup"""

    action_name: str
    status: JobStatus


class TableJobInfo(PopupJobInfo):
    """Info about the job from table row"""

    object: str
    start_date: str
    finish_date: str


JobInfo = TypeVar('JobInfo', bound=Union[PopupJobInfo, TableJobInfo])


class JobListPage(BasePageObject):
    def __init__(self, driver, base_url):
        super().__init__(driver, base_url, "/task")
        self.header = PageHeader(self.driver, self.base_url)
        self.footer = PageFooter(self.driver, self.base_url)
        self.table = CommonTableObj(self.driver, self.base_url, TaskListLocators.Table)

    def get_job_info(self, row_num: int = 0) -> TableJobInfo:
        """Get job information from row"""
        row = self.table.get_row(row_num)
        row_locators = TaskListLocators.Table.Row
        return {
            'action_name': self.find_child(row, row_locators.action_name).text,
            'object': self.find_child(row, row_locators.object).text,
            'start_date': self.find_child(row, row_locators.start_date).text,
            'finish_date': self.find_child(row, row_locators.finish_date).text,
            'status': self._get_status_from_class_string(self.find_child(row, row_locators.status)),
        }

    def get_job_info_from_popup(self, row_num: int = 0) -> PopupJobInfo:
        """Get job information from list in popup"""
        job = self.header.get_single_job_row_from_popup(row_num)
        popup_locators = AuthorizedHeaderLocators.JobPopup
        return {
            'action_name': self.find_child(job, popup_locators.job_name).text,
            'status': self._get_status_from_class_string(
                self.find_child(job, popup_locators.job_status)
            ),
        }

    @allure.step('Select the "All" filter tab')
    def select_filter_all_tab(self):
        """Show all tasks"""
        self._select_filter(TaskListLocators.Filter.all)

    @allure.step('Select the "Running" filter tab')
    def select_filter_running_tab(self):
        """Show only running tasks"""
        self._select_filter(TaskListLocators.Filter.running)

    @allure.step('Select the "Success" filter tab')
    def select_filter_success_tab(self):
        """Show only success tasks"""
        self._select_filter(TaskListLocators.Filter.success)

    @allure.step('Select the "Failed" filter tab')
    def select_filter_failed_tab(self):
        """Show only failed tasks"""
        self._select_filter(TaskListLocators.Filter.failed)

    def _select_filter(self, filter_locator: Locator):
        """Click on filter tab and wait it is pressed"""
        self.find_and_click(filter_locator)
        self.wait_element_attribute(filter_locator, 'aria-pressed', "true")
        self.wait_element_hide(CommonToolbarLocators.progress_bar)

    @staticmethod
    def _get_status_from_class_string(status_element: WebElement) -> JobStatus:
        """Get JobStatus from @class string"""
        class_string = status_element.get_attribute('class')
        for status in JobStatus:
            if status.value in class_string:
                return status
        raise KeyError('Job status not found in class string: %s' % str(class_string))
