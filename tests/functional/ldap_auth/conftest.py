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

"""Conftest for LDAP-related tests"""

from pathlib import Path
from typing import Generator

import ldap
import pytest
import yaml
from _pytest.fixtures import SubRequest
from adcm_client.objects import ADCMClient

from tests.api.utils.tools import random_string
from tests.library.ldap_interactions import LDAPTestConfig, LDAPEntityManager
from tests.library.utils import ConfigError

# pylint: disable=redefined-outer-name


@pytest.fixture(scope='session')
def ldap_config(cmd_opts) -> dict:
    """
    Load LDAP config from file as a dictionary.
    Returns empty dict if `--ldap-conf` is not presented.
    """
    if not cmd_opts.ldap_conf:
        return {}
    config_fp = Path(cmd_opts.ldap_conf)
    if not config_fp.exists():
        raise ConfigError(f'Path to LDAP config file should exist: {config_fp}')
    with config_fp.open('r', encoding='utf-8') as file:
        config = yaml.safe_load(file)
    if not isinstance(config, dict):
        raise ConfigError('LDAP config file should have root type "dict"')
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)  # pylint: disable=no-member
    return config


@pytest.fixture(scope='session')
def ad_config(ldap_config: dict) -> LDAPTestConfig:
    """Create AD config from config file"""
    required_keys = {'uri', 'admin_dn', 'admin_pass', 'base_ou_dn'}
    if 'ad' not in ldap_config:
        raise ConfigError('To test LDAP with AD LDAP config file should have "ad" key')
    config = ldap_config['ad']
    if not required_keys.issubset(config.keys()):
        raise ConfigError(
            'Not all required keys are presented in "ad" LDAP config.\n'
            f'Required: {required_keys}\n'
            f'Actual: {config.keys()}'
        )
    return LDAPTestConfig(
        config['uri'],
        config['admin_dn'],
        config['admin_pass'],
        config['base_ou_dn'],
    )


@pytest.fixture()
def ldap_ad(request: SubRequest, ad_config) -> Generator[LDAPEntityManager, None, None]:
    """Create LDAP entities manager from AD config"""
    with LDAPEntityManager(ad_config, request.node.nodeid) as ldap_manager:
        yield ldap_manager


@pytest.fixture()
def ldap_basic_ous(ldap_ad):
    """Get LDAP group (ou) DNs for users and groups"""
    groups_ou_dn = ldap_ad.create_ou('groups-main')
    users_ou_dn = ldap_ad.create_ou('users-main')
    return groups_ou_dn, users_ou_dn


@pytest.fixture()
def ldap_user(ldap_ad, ldap_basic_ous) -> dict:
    """Create LDAP AD user"""
    user = {'name': 'user_without_group', 'password': random_string(12)}
    _, users_dn = ldap_basic_ous
    user['dn'] = ldap_ad.create_user(**user, custom_base_dn=users_dn)
    return user


@pytest.fixture()
def ldap_group(ldap_ad, ldap_basic_ous) -> dict:
    """Create LDAP AD group for adding users"""
    group = {'name': 'adcm_users'}
    groups_dn, _ = ldap_basic_ous
    group['dn'] = ldap_ad.create_group(**group, custom_base_dn=groups_dn)
    return group


@pytest.fixture()
def ldap_user_in_group(ldap_ad, ldap_basic_ous, ldap_group) -> dict:
    """Create LDAP AD user and add it to a default "allowed to log to ADCM" group"""
    user = {'name': 'user_in_group', 'password': random_string(12)}
    _, users_dn = ldap_basic_ous
    user['dn'] = ldap_ad.create_user(**user, custom_base_dn=users_dn)
    ldap_ad.add_user_to_group(user['dn'], ldap_group['dn'])
    return user


@pytest.fixture()
def configure_adcm_ldap_ad(sdk_client_fs: ADCMClient, ldap_basic_ous, ldap_group, ad_config):
    """Configure ADCM to allow AD users"""
    _, users_ou = ldap_basic_ous
    adcm = sdk_client_fs.adcm()
    adcm.config_set_diff(
        {
            'attr': {'ldap_integration': {'active': True}},
            'config': {
                'ldap_integration': {
                    # now only `ldap` is allowed
                    'ldap_uri': ad_config.uri.replace('ldaps://', 'ldap://'),
                    'ldap_user': ad_config.admin_dn,
                    'ldap_password': ad_config.admin_pass,
                    'user_search_base': users_ou,
                    # now only the exact user group here allows users to log in
                    'group_search_base': ldap_group['dn'],
                }
            },
        }
    )
