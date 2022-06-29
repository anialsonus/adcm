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
from rbac.models import User, Group, OriginType
from rbac.ldap import _get_ldap_default_settings
from cm.logger import log
from django.db import DataError, IntegrityError


class SyncLDAP:
    _settings = None
    _conn = None

    @property
    def conn(self):
        if self._conn is None:
            self._conn = self._bind()
        return self._conn

    def _bind(self):
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        l = ldap.initialize(self.settings["SERVER_URI"])
        l.protocol_version = ldap.VERSION3
        try:
            l.simple_bind_s(self.settings["BIND_DN"], self.settings["BIND_PASSWORD"])
        except ldap.LDAPError as e:
            print("Error connecting to %s: %s" % (self.settings["BIND_DN"], e))
            raise
        return l

    def unbind(self):
        if self._conn is not None:
            self.conn.unbind_s()
            self._conn = None

    @property
    def settings(self):
        if self._settings is None:
            self._settings = _get_ldap_default_settings()
        return self._settings

    def sync(self):
        self.sync_groups()
        self.sync_users()

    def sync_groups(self):
        """Synchronize LDAP groups with group model and delete groups which is not found in LDAP"""
        ldap_groups = self.settings['GROUP_SEARCH'].execute(self.conn, {})
        self._sync_ldap_groups(ldap_groups)
        print("Groups are synchronized")

    def sync_users(self):
        """Synchronize LDAP users with user model and delete users which is not found in LDAP"""
        self.settings['USER_SEARCH'].filterstr = f'(objectClass=user)'
        ldap_users = self.settings['USER_SEARCH'].execute(self.conn, {'user': '*'}, True)
        self._sync_ldap_users(ldap_users)
        print("Users are synchronized")

    def _sync_ldap_groups(self, ldap_groups):
        error_names = []
        for cname, ldap_attributes in ldap_groups:
            defaults = {}

            try:
                defaults['name'] = ldap_attributes[self.settings["GROUP_TYPE"].name_attr][0]
            except KeyError:
                defaults['name'] = ''

            try:
                group, created = Group.objects.get_or_create(
                    name=defaults['name'], built_in=False, type=OriginType.LDAP
                )
            except (IntegrityError, DataError) as e:
                error_names.append(defaults['name'])
                print("Error creating group %s: %s" % (defaults['name'], e))
                continue
            else:
                if created:
                    print("Create new group: %s" % defaults['name'])
        msg = "Sync of groups ended successfully."
        msg += f"Couldn\'t synchronize groups: {error_names}" if error_names else ""
        log.debug(msg)

    def _sync_ldap_users(self, ldap_users):
        ldap_usernames = set()
        error_names = []
        for cname, ldap_attributes in ldap_users:
            defaults = {}
            for field, ldap_name in self.settings['USER_ATTR_MAP'].items():
                try:
                    defaults[field] = ldap_attributes[ldap_name][0]
                except KeyError:
                    defaults[field] = ''

            username = defaults["username"]
            kwargs = {
                'username__iexact': username,
                'type': OriginType.LDAP,
                'defaults': defaults,
            }

            try:
                user, created = User.objects.get_or_create(**kwargs)
            except (IntegrityError, DataError) as e:
                error_names.append(username)
                print("Error creating user %s: %s" % (username, e))
                continue
            else:
                updated = False
                if created:
                    print("Create user: %s" % username)
                    user.set_unusable_password()
                else:
                    for name, attr in defaults.items():
                        current_attr = getattr(user, name, None)
                        if current_attr != attr:
                            setattr(user, name, attr)
                            updated = True
                    if updated:
                        print("Updated user: %s" % username)

                user.save()
                ldap_usernames.add(username)
                for group in ldap_attributes.get('memberof', []):
                    name = group.split(',')[0][3:]
                    try:
                        group, created = Group.objects.get_or_create(name=name, built_in=False, type=OriginType.LDAP)
                        group.user_set.add(user)
                        if created:
                            print(f"Create new group: {name}")
                        print(f"Add user {user} to group {group}")
                    except (IntegrityError, DataError) as e:
                        print("Error creating group %s: %s" % (name, e))

        django_usernames = set(User.objects.filter(type=OriginType.LDAP).values_list('username', flat=True))
        for username in django_usernames - ldap_usernames:
            user = User.objects.get(username__iexact=username)
            print(f"We will delete this user: {user}")
            user.delete()
        msg = "Sync of users ended successfully."
        msg += f"Couldn\'t synchronize users: {error_names}" if error_names else ""
        log.debug(msg)


if __name__ == '__main__':
    sync_ldap = SyncLDAP()
    sync_ldap.sync()
    sync_ldap.unbind()
