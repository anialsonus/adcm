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

"""Utilities for LDAP-related tests"""

from typing import Collection

import allure
from adcm_client.base import ObjectNotFound
from adcm_client.objects import ADCMClient, Group, User

from tests.library.assertions import sets_are_equal

SYNC_ACTION_NAME = 'run_ldap_sync'
TEST_CONNECTION_ACTION = 'test_ldap_connection'
DEFAULT_LOCAL_USERS = ('admin', 'status')


def get_ldap_user_from_adcm(client: ADCMClient, name: str) -> User:
    """
    Get LDAP user from ADCM.
    Name should be sAMAccount value.
    :raises AssertionError: when there's no user presented in ADCM
    """
    username = name
    try:
        return client.user(username=username)
    except ObjectNotFound as e:
        raise AssertionError(f'LDAP user "{name}" should be available as ADCM "{username}" user') from e


def get_ldap_group_from_adcm(client: ADCMClient, name: str) -> Group:
    """
    Get LDAP group from ADCM.
    :raises AssertionError: when there's no group presented in ADCM
    """
    try:
        return client.group(name=name, type='ldap')
    except ObjectNotFound as e:
        raise AssertionError(f'LDAP group "{name}" should be available as ADCM group "{name}"') from e


@allure.step('Check users existing in ADCM')
def check_existing_users(
    client: ADCMClient, expected_ldap: Collection[str] = (), expected_local: Collection[str] = DEFAULT_LOCAL_USERS
):
    """Check that only provided users exists (both ldap and local)"""
    expected_ldap = set(expected_ldap)
    existing_ldap = {u.username for u in client.user_list() if u.type == 'ldap'}
    expected_local = set(expected_local)
    existing_local = {u.username for u in client.user_list() if u.type == 'local'}
    with allure.step('Check users from LDAP'):
        sets_are_equal(existing_ldap, expected_ldap)
    with allure.step('Check local users'):
        sets_are_equal(existing_local, expected_local)


@allure.step('Check groups existing in ADCM')
def check_existing_groups(
    client: ADCMClient, expected_ldap: Collection[str] = (), expected_local: Collection[str] = ()
):
    """Check that only provided groups exists (both ldap and local)"""
    expected_ldap = set(expected_ldap)
    existing_ldap = {g.name for g in client.group_list() if g.type == 'ldap'}
    expected_local = set(expected_local)
    existing_local = {g.name for g in client.group_list() if g.type == 'local'}
    with allure.step('Check groups from LDAP'):
        sets_are_equal(existing_ldap, expected_ldap, message='Not all LDAP groups are presented in ADCM')
    with allure.step('Check local groups'):
        sets_are_equal(existing_local, expected_local, message='Not all local groups are presented in ADCM')
