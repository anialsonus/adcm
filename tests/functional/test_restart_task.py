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

"""Tests designed to check restart method for task"""
import allure
import pytest
import requests
from adcm_client.objects import ADCMClient, Cluster, Job, Task
from adcm_pytest_plugin.utils import get_data_dir
from tests.functional.audit.conftest import (
    check_failed,
    check_succeed,
    make_auth_header,
)
from tests.functional.tools import wait_all_jobs_are_finished, wait_for_job_status
from tests.library.predicates import display_name_is
from tests.library.utils import get_or_raise

# pylint: disable=redefined-outer-name


class JobStep:
    FIRST = "first_step"
    SECOND = "second_step"
    THIRD = "third_step"


class Status:
    RUNNING = "running"
    ABORTED = "aborted"
    SUCCESS = "success"
    FAILED = "failed"


@pytest.fixture()
def cluster(sdk_client_fs) -> Cluster:
    """Create cluster and add service"""
    bundle = sdk_client_fs.upload_from_fs(get_data_dir(__file__, "cluster"))
    cluster = bundle.cluster_create("test_cluster")
    cluster.service_add(name="test_service")
    return cluster


class TestTaskCancelRestart:
    """Test to check restart tasks"""

    client: ADCMClient
    admin_creds: dict
    pytestmark = [pytest.mark.usefixtures("_init")]

    @pytest.fixture()
    def _init(self, sdk_client_fs):
        self.client = sdk_client_fs
        self.admin_creds = make_auth_header(sdk_client_fs)

    @pytest.mark.parametrize("action_name", ["one_job_success", "one_job_fail"])
    def test_restart_one_job_task(self, cluster, action_name):
        """
        Test to check that one job:
         - task with state 'created' can not be restarted
         - finished task can be restarted
         - task after restart have status running
        """
        expected_task_status = Status.SUCCESS if "success" in action_name else Status.FAILED
        with allure.step("Run task on cluster"):
            action = cluster.action(name=action_name)
            task = action.run()
            wait_for_job_status(get_or_raise(task.job_list(), display_name_is(JobStep.FIRST)))
            check_failed(self._restart_task(task=task), 409)
            self._check_task_status(task=task, expected_status=expected_task_status)

        with allure.step("Restart finished task on cluster"):
            check_succeed(self._restart_task(task=task))
            self._check_task_status(task=task, expected_status=Status.RUNNING, wait_finished=False)
            self._check_task_status(task=task, expected_status=expected_task_status)

    @pytest.mark.parametrize("action_name", ["multi_job_success", "multi_job_fail"])
    def test_restart_multi_job_task(self, cluster, action_name):
        """
        Test to check that
         - task with state 'created' can not be restarted
         - finished task can be restarted
         - after restart finished task have status running
        """
        expected_task_status = Status.SUCCESS if "success" in action_name else Status.FAILED
        with allure.step("Run task on cluster"):
            action = cluster.action(name=action_name)
            task = action.run()
            wait_for_job_status(get_or_raise(task.job_list(), display_name_is(JobStep.FIRST)))
            check_failed(self._restart_task(task=task), 409)
            wait_for_job_status(get_or_raise(task.job_list(), display_name_is(JobStep.SECOND)))
            check_failed(self._restart_task(task=task), 409)
            wait_for_job_status(get_or_raise(task.job_list(), display_name_is(JobStep.THIRD)))
            check_failed(self._restart_task(task=task), 409)
            self._check_task_status(task=task, expected_status=expected_task_status)

        with allure.step("Restart finished task on cluster"):
            check_succeed(self._restart_task(task=task))
            self._check_task_status(task=task, expected_status=Status.RUNNING, wait_finished=False)
            self._check_task_status(task=task, expected_status=expected_task_status)

    @pytest.mark.parametrize("action_name", ["multi_job_fail_second_job"])
    def test_restart_task_with_aborted_job(self, cluster, action_name):
        """
        Test to check that task where second job is failed and aborted have status success,
        but after restart task without abort failed job task status is changed to failed
        """
        with allure.step("Run task on cluster"):
            action = cluster.action(name=action_name)
            task = action.run()
            failed_job = get_or_raise(task.job_list(), display_name_is(JobStep.SECOND))
            wait_for_job_status(failed_job)
            check_succeed(self._cancel_job(failed_job))
            self._check_task_status(task=task, expected_status=Status.SUCCESS)

        with allure.step("Restart finished task on cluster"):
            check_succeed(self._restart_task(task=task))
            self._check_task_status(task=task, expected_status=Status.RUNNING, wait_finished=False)
            self._check_task_status(task=task, expected_status=Status.FAILED)

    @pytest.mark.parametrize("action_name", ["one_job_success", "one_job_fail"])
    def test_restart_aborted_task(self, cluster, action_name):
        """
        Test to check that task with aborted status can be restarted and switch status to success
        """
        expected_task_status = Status.SUCCESS if "success" in action_name else Status.FAILED
        with allure.step("Run task on cluster"):
            action = cluster.action(name=action_name)
            task = action.run()
            job = get_or_raise(task.job_list(), display_name_is(JobStep.FIRST))
            wait_for_job_status(job)
            check_succeed(self._cancel_job(job))
            self._check_task_status(task=task, expected_status=Status.ABORTED)

        with allure.step("Restart finished task on cluster"):
            check_succeed(self._restart_task(task=task))
            self._check_task_status(task=task, expected_status=Status.RUNNING, wait_finished=False)
            self._check_task_status(task=task, expected_status=expected_task_status)

    @allure.step("Restarting task")
    def _restart_task(self, task: Task):
        url = f"{self.client.url}/api/v1/task/{task.id}/restart/"
        with allure.step(f"Restart task via PUT {url}"):
            return requests.put(url, headers=self.admin_creds)

    @allure.step("Cancel job")
    def _cancel_job(self, job: Job):
        url = f"{self.client.url}/api/v1/job/{job.id}/cancel/"
        with allure.step(f"Cancel job via PUT {url}"):
            return requests.put(url, headers=self.admin_creds)

    @allure.step("Check task status")
    def _check_task_status(self, task: Task, expected_status: str, wait_finished=True) -> None:
        if wait_finished:
            wait_all_jobs_are_finished(self.client)
        task.reread()
        assert task.status == expected_status, f"Expected task status {expected_status} Actual status {task.status}"
