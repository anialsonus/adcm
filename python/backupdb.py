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

import adcm.init_django   # pylint: disable=unused-import

import datetime
import shutil
import os

from django.core.exceptions import ImproperlyConfigured
from django.db import DEFAULT_DB_ALIAS, connections
from django.db.migrations.executor import MigrationExecutor

from cm.logger import log
import cm.config as config
from adcm.settings import DATABASES


def check_migrations():
    try:
        executor = MigrationExecutor(connections[DEFAULT_DB_ALIAS])
    except ImproperlyConfigured:
        # No databases are configured (or the dummy one)
        return False
    if executor.migration_plan(executor.loader.graph.leaf_nodes()):
        return True
    return False


def backup_sqlite(dbfile):
    dt = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    backupfile = os.path.join(config.BASE_DIR, 'data', 'var', f'{dt}.db')
    shutil.copyfile(dbfile, backupfile)
    log.info('Backup sqlite db to %s', backupfile)


def backup_db():
    if not check_migrations():
        return
    db = DATABASES['default']
    if db['ENGINE'] != 'django.db.backends.sqlite3':
        log.error('Backup for %s not implemented yet', db['ENGINE'])
        return
    backup_sqlite(db['NAME'])


if __name__ == '__main__':
    backup_db()
