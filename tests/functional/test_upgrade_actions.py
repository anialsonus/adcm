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

"""
Test "scripts" section of bundle's "upgrade" section
"""

import json
import os
from typing import Set

import allure
import pytest
from coreapi.exceptions import ErrorMessage
from adcm_client.objects import Cluster, ADCMClient, Bundle
from adcm_pytest_plugin.utils import get_data_dir, catch_failed, parametrize_by_data_subdirs, random_string
from adcm_pytest_plugin.docker_utils import get_file_from_container
from adcm_pytest_plugin.steps.actions import run_cluster_action_and_assert_result

from tests.functional.conftest import only_clean_adcm
from tests.library.assertions import sets_are_equal
from tests.library.errorcodes import INVALID_UPGRADE_DEFINITION, INVALID_OBJECT_DEFINITION, ADCMError

# pylint: disable=redefined-outer-name, no-self-use

TEST_SERVICE_NAME = 'test_service'
FAILURES_DIR = 'upgrade_failures'

UPGRADE_EXTRA_ARGS = {'upgrade_with_config': {'config': {'parampampam': 'somestring'}}}


create_cluster_from_old_bundle = pytest.mark.parametrize(
    'old_cluster', [('successful', 'old')], indirect=True, ids=['successful_old_bundle']
)


def _create_old_cluster(client, *dirs):
    bundle = client.upload_from_fs(get_data_dir(__file__, *dirs))
    cluster = bundle.cluster_create('Test Cluster for Upgrade')
    cluster.service_add(name=TEST_SERVICE_NAME)
    return cluster


@pytest.fixture()
def old_cluster(request, sdk_client_fs) -> Cluster:
    """Upload old cluster bundle and then create one"""
    return _create_old_cluster(sdk_client_fs, *request.param)


class TestUpgradeActionSectionValidation:
    """Test validation of upgrade action in bundle config"""

    @parametrize_by_data_subdirs(__file__, 'validation', 'valid')
    def test_validation_succeed_on_upload(self, sdk_client_fs, path):
        """Test that valid bundles with upgrade actions succeed to upload"""
        verbose_bundle_name = os.path.basename(path).replace('_', ' ').capitalize()
        with allure.step(f'Upload bundle "{verbose_bundle_name}" and expect it to succeed'), catch_failed(
            ErrorMessage, f'Bundle "{verbose_bundle_name}" should be uploaded successfully'
        ):
            bundle = sdk_client_fs.upload_from_fs(path)
            bundle.delete()

    @pytest.mark.parametrize(
        ('bundle_dir_name', 'expected_error'),
        [
            ('bundle_switch_in_regular_actions', INVALID_OBJECT_DEFINITION),
            ('incorrect_internal_action', INVALID_UPGRADE_DEFINITION),
            ('no_bundle_switch', INVALID_UPGRADE_DEFINITION),
        ],
        ids=lambda x: f'expect_{x.code}' if isinstance(x, ADCMError) else str(x),
    )
    def test_validation_failed_on_upload(self, bundle_dir_name, expected_error, sdk_client_fs):
        """Test that invalid bundles with upgrade actions fails to upload"""
        verbose_bundle_name = bundle_dir_name.replace('_', ' ').capitalize()
        invalid_bundle_file = get_data_dir(__file__, 'validation', 'invalid', bundle_dir_name)
        with allure.step(f'Upload bundle "{verbose_bundle_name}" and expect upload to fail'):
            with pytest.raises(ErrorMessage) as e:
                sdk_client_fs.upload_from_fs(invalid_bundle_file)
            expected_error.equal(e)


@create_cluster_from_old_bundle
class TestSuccessfulUpgrade:
    """Test successful scenarios of upgrade actions"""

    @pytest.mark.parametrize(
        'upgrade_name',
        ['simple_upgrade', 'upgrade_with_config', 'upgrade_with_non_default_venv'],
    )
    def test_successful_upgrade(self, upgrade_name, old_cluster: Cluster, sdk_client_fs):
        """Test successful upgrade scenarios"""
        upgrade_config = UPGRADE_EXTRA_ARGS.get(upgrade_name, {})
        self._run_successful_upgrade(sdk_client_fs, old_cluster, upgrade_name, upgrade_config)

    def test_successful_upgrade_with_content_change(self, sdk_client_fs, old_cluster):
        """
        Test successful upgrade with changing content of action file
        and expect new content to be executed
        """
        upgrade_name = 'file_content_changed'
        expected_message = 'This message came from the new bundle!'
        self._run_successful_upgrade(sdk_client_fs, old_cluster, upgrade_name, {})
        for job_name in ('before_switch', 'after_switch'):
            job = next(
                filter(
                    lambda x: x.display_name == job_name, sdk_client_fs.job_list()  # pylint: disable=cell-var-from-loop
                )
            )
            assert expected_message in job.log().content, f'"{expected_message}" should be in log'

    @only_clean_adcm
    def test_inventories(self, adcm_fs, sdk_client_fs, old_cluster):
        """Check that inventories of jobs before and after bundle switch are correct"""
        upgrade_name = 'simple_upgrade'
        job_before_id = 1
        job_after_id = 3

        self._run_successful_upgrade(sdk_client_fs, old_cluster, upgrade_name, {})
        with allure.step('Check inventory of job before the bundle_switch'):
            _compare_inventory_files(adcm_fs, job_before_id)
        with allure.step('Check inventory of job after the bundle_switch'):
            _compare_inventory_files(adcm_fs, job_after_id)

    def _run_successful_upgrade(self, client, old_cluster, upgrade_name, upgrade_config):
        with allure.step('Upload new version of cluster bundle'):
            new_bundle = client.upload_from_fs(get_data_dir(__file__, 'successful', 'new'))
        with allure.step('Run upgrade and expect it to be successful'):
            upgrade_task = old_cluster.upgrade(name=upgrade_name).do(**upgrade_config)
            assert upgrade_task.wait() == 'success', f'Upgrade {upgrade_name} failed unexpectedly'
            check_state(old_cluster, 'ready_to_upgrade')
        with allure.step('Check that prototype was upgraded successfully'):
            check_prototype(old_cluster, new_bundle.cluster_prototype().id)
            check_cluster_objects_configs_equal_bundle_default(old_cluster, new_bundle)


@pytest.mark.parametrize('old_cluster', [(FAILURES_DIR, 'old')], indirect=True, ids=['failures_old_bundle'])
class TestFailedUpgradeAction:
    """Test cases when upgrade action is failed during execution"""

    def test_fail_before_switch(self, sdk_client_fs, old_cluster):
        """
        Test bundle action fails before bundle_switch was performed
        """
        old_bundle = old_cluster.bundle()
        expected_state = old_cluster.state
        expected_prototype_id = old_cluster.prototype_id

        self._upload_new_version(sdk_client_fs, 'before_switch')
        self._upgrade_and_expect_state(old_cluster, expected_state)
        check_prototype(old_cluster, expected_prototype_id)
        check_cluster_objects_configs_equal_bundle_default(old_cluster, old_bundle)

    def test_fail_after_switch_with_on_fail(self, sdk_client_fs, old_cluster):
        """
        Test bundle action fails after bundle_switch was performed.
        Failed job has "on_fail" directive.
        """
        restore_action_name = 'restore'
        expected_state = 'something_is_wrong'
        expected_state_after_restore = 'upgraded'

        bundle = self._upload_new_version(sdk_client_fs, 'after_switch_with_on_fail')
        expected_prototype_id = bundle.cluster_prototype().id
        self._upgrade_and_expect_state(old_cluster, expected_state)
        check_prototype(old_cluster, expected_prototype_id)
        check_cluster_objects_configs_equal_bundle_default(old_cluster, bundle)
        self._check_action_list(old_cluster, {restore_action_name})
        run_cluster_action_and_assert_result(old_cluster, restore_action_name)
        check_state(old_cluster, expected_state_after_restore)

    def test_fail_after_switch_without_on_fail(self, sdk_client_fs, old_cluster):
        """
        Test bundle action fails after bundle_switch was performed.
        Failed job doesn't have "on_fail" directive.
        """
        expected_state = old_cluster.state

        bundle = self._upload_new_version(sdk_client_fs, 'after_switch')
        expected_prototype_id = bundle.cluster_prototype().id
        self._upgrade_and_expect_state(old_cluster, expected_state)
        check_prototype(old_cluster, expected_prototype_id)
        check_cluster_objects_configs_equal_bundle_default(old_cluster, bundle)
        self._check_action_list(old_cluster, set())

    @pytest.mark.parametrize(
        'upgrade_name',
        ['fail_after_bundle_switch', 'fail_before_bundle_switch'],
        ids=['fail_before_switch', 'fail_after_switch'],
    )
    def test_fail_with_both_action_states_set(self, upgrade_name: str, sdk_client_fs, old_cluster):
        """
        Test bundle action fails before/after bundle_switch
        when both on_success and on_fail are presented in action block
        """
        self._upload_new_version(sdk_client_fs, 'upgrade_action_has_on_fail')
        self._upgrade_and_expect_state(old_cluster, 'something_failed', name=upgrade_name)

    @allure.step('Upload new version of cluster bundle')
    def _upload_new_version(self, client: ADCMClient, name: str) -> Bundle:
        """Upload new version of bundle based on the given bundle file_name"""
        return client.upload_from_fs(get_data_dir(__file__, FAILURES_DIR, name))

    @allure.step('Upgrade cluster and expect it to enter the "{state}" state')
    def _upgrade_and_expect_state(self, cluster: Cluster, state: str, **kwargs):
        """
        Upgrade cluster to a new version (expect upgrade to fail)
        and check if it's state is correct
        """
        task = cluster.upgrade(**kwargs).do()
        assert task.wait() == 'failed', 'Upgrade action should have failed'
        check_state(cluster, state)

    @allure.step('Check list of available actions on cluster')
    def _check_action_list(self, cluster: Cluster, action_names: Set[str]):
        """Check that action list is equal to given one (by names)"""
        cluster.reread()
        presented_action_names = {a.name for a in cluster.action_list()}
        sets_are_equal(presented_action_names, action_names, message='Incorrect action list')


@allure.step('Check cluster state is equal to "{state}"')
def check_state(cluster: Cluster, state: str):
    """Check state of a cluster"""
    cluster.reread()
    assert (actual_state := cluster.state) == state, f'State after failed upgrade should be {state}, not {actual_state}'


@allure.step('Check that cluster prototype is equal to {expected_prototype_id}')
def check_prototype(cluster: Cluster, expected_prototype_id: int):
    """Check that prototype of a cluster is the same as expected"""
    cluster.reread()
    assert (
        actual_id := cluster.prototype_id
    ) == expected_prototype_id, f'Prototype of cluster should be {expected_prototype_id}, not {actual_id}'


def check_cluster_objects_configs_equal_bundle_default(
    cluster: Cluster, bundle: Bundle, *, service_name: str = 'test_service'
):
    """
    Check that configurations of cluster, its services and components
    are equal to configurations of newly created cluster from given bundle
    """
    with allure.step(
        f'Check configuration of cluster {cluster.name} is equal to default configuration of cluster from {bundle.name}'
    ):
        actual_configs = _extract_configs(cluster)
        cluster_with_defaults = bundle.cluster_create(f'Cluster to take config from {random_string(4)}')
        cluster_with_defaults.service_add(name=service_name)
        expected_configs = _extract_configs(cluster_with_defaults)

        if actual_configs == expected_configs:
            return
        allure.attach(
            json.dumps(expected_configs, indent=2),
            name='Expected cluster objects configuration',
            attachment_type=allure.attachment_type.JSON,
        )
        allure.attach(
            json.dumps(actual_configs, indent=2),
            name='Actual cluster objects configuration',
            attachment_type=allure.attachment_type.JSON,
        )
        raise AssertionError("Cluster objects' configs aren't equal to expected, check attachments for more details")


def _compare_inventory_files(adcm_fs, job_id: int):
    """Compare two inventory files: one from local storage (expected) and one from docker container with ADCM"""
    inventory_file = get_file_from_container(adcm_fs, f'/adcm/data/run/{job_id}/', 'inventory.json')
    actual_inventory = json.loads(inventory_file.read().decode('utf-8'))
    with open(get_data_dir(__file__, 'successful', f'inventory_{job_id}.json'), 'rb') as file:
        expected_inventory = json.load(file)
    if actual_inventory == expected_inventory:
        return
    allure.attach(
        json.dumps(expected_inventory, indent=2),
        name=f'Expected inventory of job {job_id}',
        attachment_type=allure.attachment_type.JSON,
    )
    allure.attach(
        json.dumps(actual_inventory, indent=2),
        name=f'Actual inventory of job {job_id}',
        attachment_type=allure.attachment_type.JSON,
    )
    raise AssertionError(f'Inventories should be equal for job {job_id}.\nSee attachments for more details.')


def _extract_configs(cluster: Cluster):
    """Extract configurations of the cluster, its services and components as dict"""
    return {
        'config': dict(cluster.config()),
        'services': {
            service.name: {
                'config': dict(service.config()),
                'components': {
                    component.name: {'config': dict(component.config())} for component in service.component_list()
                },
            }
            for service in cluster.service_list()
        },
    }
