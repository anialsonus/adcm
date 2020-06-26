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
# pylint: disable=W0621, R0912
import os

import coreapi
import pytest
import yaml
from adcm_client.base import ActionHasIssues
from adcm_client.objects import ADCMClient, Cluster, Service, Provider, Host
from adcm_pytest_plugin.utils import fixture_parametrized_by_data_subdirs


def get_sent_value(path, entity):
    if isinstance(entity, Cluster):
        file_name = os.path.join(path, 'cluster', 'cluster_action.yaml')
    if isinstance(entity, Service):
        file_name = os.path.join(path, 'cluster', 'service_action.yaml')
    if isinstance(entity, Provider):
        file_name = os.path.join(path, 'provider', 'provider_action.yaml')
    if isinstance(entity, Host):
        file_name = os.path.join(path, 'provider', 'host_action.yaml')

    with open(file_name, 'r') as f:
        data = yaml.full_load(f)
        playbook_vars = data[0]['vars']
        return playbook_vars['sent_config_value']


def processing_data(sdk_client_ms, request, variant):
    path = request.param
    config_type = os.path.split(path)[1]
    cluster_bundle = sdk_client_ms.upload_from_fs(os.path.join(path, 'cluster'))
    provider_bundle = sdk_client_ms.upload_from_fs(os.path.join(path, 'provider'))

    cluster = cluster_bundle.cluster_create(f'cluster_{variant}')
    service = cluster.service_add(
        name=f'service_{config_type}_{variant}')

    provider = provider_bundle.provider_create(f'provider_{variant}')
    host = provider.host_create(f'host_{config_type}_{variant}')
    cluster.host_add(host)
    return path, config_type, [cluster, provider, service, host]


def assert_config_type(path, config_type, entities, is_required, is_default, sent_value_type):
    for entity in entities:
        if is_required and sent_value_type != 'correct_value':
            sent_data = {config_type: get_sent_value(path, entity)}

            if config_type == 'list' and sent_value_type == 'empty_value':
                assert entity.config_set(sent_data) == sent_data
            else:
                with pytest.raises(coreapi.exceptions.ErrorMessage) as error:
                    entity.config_set(sent_data)
                assert error.value.error['code'] == 'CONFIG_VALUE_ERROR'

            if is_default:
                action_status = entity.action_run(name='job').wait()
                assert action_status == 'success'
            else:
                if sent_value_type == 'empty_value':
                    if isinstance(entity, Cluster):
                        with pytest.raises(ActionHasIssues) as error:
                            entity.action_run(name='job').wait()
                    else:
                        action_status = entity.action_run(name='job').wait()
                        assert action_status == 'success'
                else:
                    with pytest.raises(ActionHasIssues) as error:
                        entity.action_run(name='job').wait()
        else:
            sent_data = {config_type: get_sent_value(path, entity)}
            assert entity.config_set(sent_data) == sent_data
            if is_required:
                if is_default:
                    action_status = entity.action_run(name='job').wait()
                    assert action_status == 'success'
                else:
                    if isinstance(entity, Cluster):
                        with pytest.raises(ActionHasIssues) as error:
                            entity.action_run(name='job').wait()
                    else:
                        action_status = entity.action_run(name='job').wait()
                        assert action_status == 'success'
            else:
                action_status = entity.action_run(name='job').wait()
                assert action_status == 'success'


@fixture_parametrized_by_data_subdirs(
    __file__, 'not_required', 'with_default', 'sent_correct_value', scope='module')
def nr_wd_cv(sdk_client_ms: ADCMClient, request):
    return processing_data(sdk_client_ms, request, 'not_required_with_default_sent_correct_value')


@fixture_parametrized_by_data_subdirs(
    __file__, 'not_required', 'with_default', 'sent_empty_value', scope='module')
def nr_wd_ev(sdk_client_ms: ADCMClient, request):
    return processing_data(sdk_client_ms, request, 'not_required_with_default_sent_empty_value')


@fixture_parametrized_by_data_subdirs(
    __file__, 'not_required', 'with_default', 'sent_null_value', scope='module')
def nr_wd_nv(sdk_client_ms: ADCMClient, request):
    return processing_data(sdk_client_ms, request, 'not_required_with_default_sent_null_value')


def test_not_required_with_default_sent_correct_value(nr_wd_cv):
    assert_config_type(*nr_wd_cv, False, True, 'correct_value')


def test_not_required_with_default_sent_empty_value(nr_wd_ev):
    assert_config_type(*nr_wd_ev, False, True, 'empty_value')


def test_not_required_with_default_sent_null_value(nr_wd_nv):
    assert_config_type(*nr_wd_nv, False, True, 'null_value')


@fixture_parametrized_by_data_subdirs(
    __file__, 'not_required', 'without_default', 'sent_correct_value', scope='module')
def nr_wod_cv(sdk_client_ms: ADCMClient, request):
    return processing_data(
        sdk_client_ms, request, 'not_required_without_default_sent_correct_value')


@fixture_parametrized_by_data_subdirs(
    __file__, 'not_required', 'without_default', 'sent_empty_value', scope='module')
def nr_wod_ev(sdk_client_ms: ADCMClient, request):
    return processing_data(sdk_client_ms, request, 'not_required_without_default_sent_empty_value')


@fixture_parametrized_by_data_subdirs(
    __file__, 'not_required', 'without_default', 'sent_null_value', scope='module')
def nr_wod_nv(sdk_client_ms: ADCMClient, request):
    return processing_data(sdk_client_ms, request, 'not_required_without_default_sent_null_value')


def test_not_required_without_default_sent_correct_value(nr_wod_cv):
    assert_config_type(*nr_wod_cv, False, False, 'correct_value')


def test_not_required_without_default_sent_empty_value(nr_wod_ev):
    assert_config_type(*nr_wod_ev, False, False, 'empty_value')


def test_not_required_without_default_sent_null_value(nr_wod_nv):
    assert_config_type(*nr_wod_nv, False, False, 'null_value')


@fixture_parametrized_by_data_subdirs(
    __file__, 'required', 'with_default', 'sent_correct_value', scope='module')
def r_wd_cv(sdk_client_ms: ADCMClient, request):
    return processing_data(sdk_client_ms, request, 'required_with_default_sent_correct_value')


@fixture_parametrized_by_data_subdirs(
    __file__, 'required', 'with_default', 'sent_empty_value', scope='module')
def r_wd_ev(sdk_client_ms: ADCMClient, request):
    return processing_data(sdk_client_ms, request, 'required_with_default_sent_empty_value')


@fixture_parametrized_by_data_subdirs(
    __file__, 'required', 'with_default', 'sent_null_value', scope='module')
def r_wd_nv(sdk_client_ms: ADCMClient, request):
    return processing_data(sdk_client_ms, request, 'required_with_default_sent_null_value')


def test_required_with_default_sent_correct_value(r_wd_cv):
    assert_config_type(*r_wd_cv, True, True, 'correct_value')


def test_required_with_default_sent_empty_value(r_wd_ev):
    assert_config_type(*r_wd_ev, True, True, 'empty_value')


def test_required_with_default_sent_null_value(r_wd_nv):
    assert_config_type(*r_wd_nv, True, True, 'null_value')


@fixture_parametrized_by_data_subdirs(
    __file__, 'required', 'without_default', 'sent_correct_value', scope='module')
def r_wod_cv(sdk_client_ms: ADCMClient, request):
    return processing_data(
        sdk_client_ms, request, 'required_without_default_sent_correct_value')


@fixture_parametrized_by_data_subdirs(
    __file__, 'required', 'without_default', 'sent_empty_value', scope='module')
def r_wod_ev(sdk_client_ms: ADCMClient, request):
    return processing_data(sdk_client_ms, request, 'required_without_default_sent_empty_value')


@fixture_parametrized_by_data_subdirs(
    __file__, 'required', 'without_default', 'sent_null_value', scope='module')
def r_wod_nv(sdk_client_ms: ADCMClient, request):
    return processing_data(sdk_client_ms, request, 'required_without_default_sent_null_value')


def test_required_without_default_sent_correct_value(r_wod_cv):
    assert_config_type(*r_wod_cv, True, False, 'correct_value')


def test_required_without_default_sent_empty_value(r_wod_ev):
    assert_config_type(*r_wod_ev, True, False, 'empty_value')


def test_required_without_default_sent_null_value(r_wod_nv):
    assert_config_type(*r_wod_nv, True, False, 'null_value')
