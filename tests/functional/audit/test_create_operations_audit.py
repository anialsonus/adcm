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
Test audit operations with "operation_type == CREATE"
"""

from pathlib import Path
from typing import Optional, Callable, Dict

import allure
import pytest
import requests
from adcm_client.objects import ADCMClient

from tests.functional.audit.conftest import BUNDLES_DIR, parametrize_audit_scenario_parsing

from tests.library.audit.checkers import AuditLogChecker


# pylint: disable=redefined-outer-name

NEW_USER = {
    'username': 'newuser',
    'password': 'fnwqoevj',
    'first_name': 'young',
    'last_name': 'manager',
    'email': 'does@notexi.st',
}


class CreateOperation:
    """List of endpoints for convenience"""

    # UPLOAD
    LOAD = 'stack/load'
    UPLOAD = 'stack/upload'
    # CREATE CLUSTER/PROVIDER objects
    CLUSTER = 'cluster'
    PROVIDER = 'provider'
    HOST = 'host'
    HOST_FROM_PROVIDER = 'provider/{provider_id}/host'
    # GROUP CONFIG
    GROUP_CONFIG = 'group-config'
    # RBAC
    USER = 'rbac/user'
    ROLE = 'rbac/role'
    GROUP = 'rbac/group'
    POLICY = 'rbac/policy'


@pytest.fixture()
def post(sdk_client_fs) -> Callable:
    """
    Prepare POST caller with all required credentials, so you only need to give path.
    Body and stuff are optional.
    """
    base_url = sdk_client_fs.url
    auth_header = _make_auth_header(sdk_client_fs)

    def _post(
        path: str,
        body: Optional[dict] = None,
        headers: Optional[dict] = None,
        path_fmt: Optional[dict] = None,
        **kwargs,
    ):
        body = {} if body is None else body
        headers = {**auth_header, **({} if headers is None else headers)}
        path_fmt = {} if path_fmt is None else path_fmt
        url = f'{base_url}/api/v1/{path.format(**path_fmt)}/'
        with allure.step(f'Sending post request to {url}'):
            return requests.post(url, headers=headers, json=body, **kwargs)

    return _post


@pytest.fixture()
def rbac_create_data(sdk_client_fs) -> Dict[str, dict]:
    """Prepare data to create RBAC objects"""
    business_role = sdk_client_fs.role(name='View ADCM settings')
    adcm_user_role = sdk_client_fs.role(name='ADCM User')
    return {
        'user': {**NEW_USER},
        'group': {'name': 'groupforU'},
        'role': {
            'name': 'newrole',
            'description': 'Awesome role',
            'display_name': 'New Role',
            'child': [{'id': business_role.id}],
        },
        'policy': {
            'name': 'newpolicy',
            'description': 'Best policy ever',
            'role': {'id': adcm_user_role.id},
            'user': [{'id': sdk_client_fs.me().id}],
            'group': [],
            'object': [],
        },
    }


@pytest.fixture()
def new_user_client(sdk_client_fs) -> ADCMClient:
    """Create new user"""
    user = sdk_client_fs.user_create(**NEW_USER)
    return ADCMClient(url=sdk_client_fs.url, user=user.username, password=NEW_USER['password'])


@pytest.mark.parametrize(
    'bundle_archives',
    [
        [
            str(BUNDLES_DIR / 'create' / bundle_dir)
            for bundle_dir in ('incorrect_cluster', 'incorrect_provider', 'cluster', 'provider')
        ]
    ],
    indirect=True,
)
@parametrize_audit_scenario_parsing('create_load_upload.yaml', NEW_USER)
def test_bundle_upload_load(audit_log_checker, post, bundle_archives, sdk_client_fs, new_user_client):
    """Test audit logs for CREATE operations: stack/upload and stack/load"""
    incorrect_cluster_bundle, incorrect_provider_bundle, cluster_bundle, provider_bundle = tuple(
        map(Path, bundle_archives)
    )
    unauthorized_user_creds = _make_auth_header(new_user_client)
    with allure.step('Upload and load incorrect bundles (as unauthorized and authorized user)'):
        for bundle_path in (incorrect_cluster_bundle, incorrect_provider_bundle):
            with bundle_path.open('rb') as f:
                _check_failed(post(CreateOperation.UPLOAD, files={'file': f}, headers=unauthorized_user_creds), 403)
            with bundle_path.open('rb') as f:
                _check_succeed(post(CreateOperation.UPLOAD, files={'file': f}))
            _check_failed(
                post(CreateOperation.LOAD, {'bundle_file': bundle_path.name}, headers=unauthorized_user_creds), 403
            )
            _check_failed(post(CreateOperation.LOAD, {'bundle_file': bundle_path.name}))
    with allure.step('Upload and load correct bundles (as unauthorized and authorized user)'):
        for bundle_path in (cluster_bundle, provider_bundle):
            with bundle_path.open('rb') as f:
                _check_failed(post(CreateOperation.UPLOAD, files={'file': f}, headers=unauthorized_user_creds), 403)
            with bundle_path.open('rb') as f:
                _check_succeed(post(CreateOperation.UPLOAD, files={'file': f}))
            _check_failed(
                post(CreateOperation.LOAD, {'bundle_file': bundle_path.name}, headers=unauthorized_user_creds), 403
            )
            _check_succeed(post(CreateOperation.LOAD, {'bundle_file': bundle_path.name}))
    with allure.step('Load/Upload with incorrect data in request (as unauthorized and authorized user)'):
        _check_failed(post(CreateOperation.UPLOAD, files={'wrongkey': 'sldkj'}, headers=unauthorized_user_creds), 403)
        _check_failed(post(CreateOperation.LOAD, {'bundle': 'somwthign'}, headers=unauthorized_user_creds), 403)
        _check_failed(post(CreateOperation.UPLOAD, files={'wrongkey': 'sldkj'}))
        _check_failed(post(CreateOperation.LOAD, {'bundle': 'somwthign'}))
    audit_log_checker.check(sdk_client_fs.audit_operation_list())


def test_rbac_create_operations(audit_log_scenarios_reader, rbac_create_data, post, sdk_client_fs):
    """Test audit logs for CREATE of RBAC objects"""
    audit_checker = AuditLogChecker(audit_log_scenarios_reader.parse('create_rbac_entities.yaml', rbac_create_data))
    with allure.step('Create user, try to create its duplicate and make it as an unauthorized user'):
        user_info = rbac_create_data.pop('user')
        _check_succeed(post(CreateOperation.USER, user_info))
        new_user_auth_header = _make_auth_header(
            ADCMClient(url=sdk_client_fs.url, user=user_info['username'], password=user_info['password'])
        )
        _check_failed(post(CreateOperation.USER, user_info))
        _check_failed(post(CreateOperation.USER, user_info, headers=new_user_auth_header), 403)

    for object_type, create_data in rbac_create_data.items():
        with allure.step(f'Create {object_type}, try to create its duplicate and make it as an unauthorized user'):
            _check_succeed(post(getattr(CreateOperation, object_type.upper()), create_data))
            _check_failed(post(getattr(CreateOperation, object_type.upper()), create_data))
            _check_failed(
                post(getattr(CreateOperation, object_type.upper()), create_data, headers=new_user_auth_header), 403
            )
    audit_checker.check(sdk_client_fs.audit_operation_list())


@allure.step('Expecting request to succeed')
def _check_succeed(response: requests.Response):
    assert response.status_code in (
        200,
        201,
    ), f'Request failed with code: {response.status_code}\nBody: {response.json()}'


def _check_failed(response: requests.Response, exact_code: Optional[int] = None):
    with allure.step(f'Expecting request to fail with code {exact_code if exact_code else ">=400 and < 500"}'):
        assert response.status_code < 500, 'Request should not failed with 500'
        if exact_code:
            assert (
                response.status_code == exact_code
            ), f'Request was expected to be failed with {exact_code}, not {response.status_code}'
        else:
            assert response.status_code >= 400, (
                'Request was expected to be failed, '
                f'but status code was {response.status_code}.\nBody: {response.json()}'
            )


def _make_auth_header(client: ADCMClient) -> dict:
    return {'Authorization': f'Token {client.api_token()}'}
