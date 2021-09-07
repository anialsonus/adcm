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
import allure
from adcm_client.objects import ADCMClient, Provider, Cluster
from adcm_pytest_plugin.utils import get_data_dir, fixture_parametrized_by_data_subdirs


@fixture_parametrized_by_data_subdirs(__file__, 'cluster_and_service')
def cluster(sdk_client_fs: ADCMClient, request):
    bundle = sdk_client_fs.upload_from_fs(request.param)
    cluster = bundle.cluster_create(name=bundle.name)
    cluster.service_add(name='multi')
    return cluster


def test_cluster_state_after_multijob(sdk_client_fs: ADCMClient, cluster):
    with allure.step('Run action: multi'):
        cluster.action(name="multi").run().wait()
    with allure.step('Check cluster state'):
        assert sdk_client_fs.cluster(name=cluster.name).state == cluster.name


def test_service_state_after_multijob(cluster: Cluster):
    with allure.step('Run action: multi'):
        cluster.service(name='multi').action(name="multi").run().wait()
    with allure.step('Check service state'):
        assert cluster.service(name='multi').state == cluster.name


def test_cluster_service_state_locked(sdk_client_fs: ADCMClient):
    with allure.step('Create cluster'):
        bundle = sdk_client_fs.upload_from_fs(get_data_dir(__file__, 'cluster_and_service_lock'))
        cluster = bundle.cluster_create(name=bundle.name)
    with allure.step('Add services multi and stab'):
        cluster.service_add(name='multi')
        cluster.service_add(name='stab')
    with allure.step('Check that services is not locked and its state is created'):
        assert bundle.cluster(name=bundle.name).state == 'created'
        assert bundle.cluster(name=bundle.name).service(name='multi').state == 'created'
        assert bundle.cluster(name=bundle.name).service(name='stab').state == 'created'
        assert bundle.cluster(name=bundle.name).locked is False
        assert bundle.cluster(name=bundle.name).service(name='multi').locked is False
        assert bundle.cluster(name=bundle.name).service(name='stab').locked is False
    with allure.step('Run cluster action: multi'):
        task = cluster.action(name='multi').run()
    with allure.step('Check services: locked and then free'):
        assert bundle.cluster(name=bundle.name).state == 'created'
        assert bundle.cluster(name=bundle.name).service(name='multi').state == 'created'
        assert bundle.cluster(name=bundle.name).service(name='stab').state == 'created'
        assert bundle.cluster(name=bundle.name).locked is True
        assert bundle.cluster(name=bundle.name).service(name='multi').locked is True
        assert bundle.cluster(name=bundle.name).service(name='stab').locked is True
        task.wait()
        assert bundle.cluster(name=bundle.name).state == 'multi_ok'
        assert bundle.cluster(name=bundle.name).locked is False
        assert bundle.cluster(name=bundle.name).service(name='multi').locked is False
        assert bundle.cluster(name=bundle.name).service(name='stab').locked is False
    with allure.step('Run service action: multi'):
        task = cluster.service(name='multi').action(name='multi').run()
    with allure.step('Check services states: locked and created'):
        assert bundle.cluster(name=bundle.name).locked is True
        assert bundle.cluster(name=bundle.name).service(name='multi').locked is True
        assert bundle.cluster(name=bundle.name).service(name='stab').locked is False
        task.wait()
        assert bundle.cluster(name=bundle.name).state == 'multi_ok'
        assert bundle.cluster(name=bundle.name).locked is False
        assert bundle.cluster(name=bundle.name).service(name='multi').state == 'multi_ok'
        assert bundle.cluster(name=bundle.name).service(name='multi').locked is False
        assert bundle.cluster(name=bundle.name).service(name='stab').locked is False


@fixture_parametrized_by_data_subdirs(__file__, 'provider_and_host')
def provider(sdk_client_fs: ADCMClient, request):
    bundle = sdk_client_fs.upload_from_fs(request.param)
    provider = bundle.provider_create(name=bundle.name)
    provider.host_create(fqdn=bundle.name)
    return provider


def test_provider_state_after_multijob(sdk_client_fs: ADCMClient, provider):
    with allure.step('Run provider action: multi'):
        provider.action(name="multi").run().wait()
    with allure.step('Check provider state'):
        assert sdk_client_fs.provider(name=provider.name).state == provider.name


def test_host_state_after_multijob(provider: Provider):
    with allure.step('Run host action: multi'):
        provider.host(fqdn=provider.name).action(name="multi").run().wait()
    with allure.step('Check host state'):
        assert provider.host(fqdn=provider.name).state == provider.name
