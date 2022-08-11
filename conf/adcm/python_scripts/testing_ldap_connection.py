#!/usr/bin/env python3
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

import os
import sys
import ldap

os.environ["PYTHONPATH"] = "/adcm/python/"
sys.path.append("/adcm/python/")

import adcm.init_django  # pylint: disable=unused-import
from rbac.ldap import _get_ldap_default_settings, configure_tls, is_tls
from cm.errors import AdcmEx

CERT_ENV_KEY = 'LDAPTLS_CACERT'


def bind():
    ldap_config, error_code = _get_ldap_default_settings()
    if error_code is not None:
        error = AdcmEx(error_code)
        sys.stdout.write(error.msg)
        raise error
    if ldap_config:
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        ldap_URI = ldap_config['SERVER_URI']
        try:
            conn = ldap.initialize(ldap_URI)
            conn.protocol_version = ldap.VERSION3
            configure_tls(is_tls(ldap_URI), os.environ.get(CERT_ENV_KEY, ''), conn)
            conn.simple_bind_s(ldap_config['BIND_DN'], ldap_config['BIND_PASSWORD'])
        except ldap.LDAPError as e:
            sys.stdout.write(f"Can't connect to {ldap_URI} with user: {ldap_config['BIND_DN']}. Error: {e}\n")
            raise
        sys.stdout.write(f"Connection successful to {ldap_URI}\n")


if __name__ == '__main__':
    bind()
