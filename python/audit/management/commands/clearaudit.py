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

import csv
import os
from datetime import timedelta
from shutil import rmtree
from tarfile import TarFile

from django.core.management.base import BaseCommand
from django.utils import timezone

from audit.models import AuditLog, AuditObject, AuditSession
from audit.utils import make_audit_log
from cm.logger import log_cron_task as log
from cm.adcm_config import get_adcm_config


# pylint: disable=protected-access
class Command(BaseCommand):
    encoding = 'utf-8'
    config_key = 'audit_data_retention'
    archive_base_dir = '/adcm/data/audit/'
    archive_tmp_dir = '/adcm/data/audit/tmp'
    archive_name = 'audit_archive.tar.gz'
    tarfile_cfg = dict(
        read=dict(
            name=os.path.join(archive_base_dir, archive_name),
            mode='r:gz',
            encoding='utf-8',
        ),
        write=dict(
            name=os.path.join(archive_base_dir, archive_name),
            mode='w:gz',
            encoding='utf-8',
            compresslevel=9,
        ),
    )

    archive_model_postfix_map = {
        AuditLog._meta.object_name: 'operations',
        AuditSession._meta.object_name: 'logins',
    }

    def handle(self, *args, **options):
        try:
            _, config = get_adcm_config(self.config_key)
            if config['retention_period'] <= 0:
                self.__log('Disabled')
                return

            threshold_date = timezone.now() - timedelta(days=config['retention_period'])
            self.__log(f'Started. Threshold date: {threshold_date}')

            target_operations = AuditLog.objects.filter(operation_time__lt=threshold_date)
            target_logins = AuditSession.objects.filter(login_time__lt=threshold_date)
            cleared = False
            if target_operations or target_logins:
                make_audit_log('audit', 'success', 'launched')

            if config['data_archiving']:
                self.__log(
                    f'Target audit records will be archived to '
                    f'`{os.path.join(self.archive_base_dir, self.archive_name)}`'
                )
                self.__archive(target_operations, target_logins)
            else:
                self.__log('Archiving is disabled')

            if target_operations.exists():
                self.__log(f'Deleting {target_operations.count()} AuditLog')
                target_operations.delete()
                cleared = True
            if target_logins.exists():
                self.__log(f'Deleting {target_logins.count()} AuditSession')
                target_logins.delete()
                cleared = True

            objects_pk_to_delete = set()
            for ao in AuditObject.objects.filter(is_deleted=True):
                if not ao.auditlog_set.exists():
                    objects_pk_to_delete.add(ao.pk)
            target_objects = AuditObject.objects.filter(pk__in=objects_pk_to_delete)

            if target_objects.exists():
                self.__log(f'Deleting {target_objects.count()} AuditObject')
                target_objects.delete()
                cleared = True

            self.__log('Finished.')
            if cleared:
                make_audit_log('audit', 'success', 'completed')
        except Exception as e:  # pylint: disable=broad-except
            make_audit_log('audit', 'failed', 'completed')
            self.__log('Error in auditlog rotation')
            self.__log(e)

    def __archive(self, *querysets):
        os.makedirs(self.archive_base_dir, exist_ok=True)
        os.makedirs(self.archive_tmp_dir, exist_ok=True)

        self.__extract_to_tmp_dir()
        csv_files = self.__prepare_csvs(*querysets, base_dir=self.archive_tmp_dir)
        if not csv_files:
            self.__log('No targets for archiving')
        self.__archive_tmp_dir()
        self.__log(f'Files `{csv_files}` added to archive `{self.archive_name}`')

    def __extract_to_tmp_dir(self):
        if not os.path.exists(self.tarfile_cfg['read']['name']):
            return
        with TarFile.open(**self.tarfile_cfg['read']) as tar:
            tar.extractall(path=self.archive_tmp_dir)
        os.remove(self.tarfile_cfg['read']['name'])

    def __archive_tmp_dir(self):
        with TarFile.open(**self.tarfile_cfg['write']) as tar:
            for f in os.listdir(self.archive_tmp_dir):
                tar.add(name=os.path.join(self.archive_tmp_dir, f), arcname=f)
        rmtree(self.archive_tmp_dir, ignore_errors=True)

    def __prepare_csvs(self, *querysets, base_dir):
        now = timezone.now().date()

        csv_files = []
        for qs in querysets:
            if not qs.exists():
                continue

            tmp_cvf_name = self.__get_csv_name(qs, now, base_dir)
            with open(tmp_cvf_name, 'wt', newline='', encoding=self.encoding) as csv_file:
                writer = csv.writer(csv_file)

                field_names = [f.name for f in qs.model._meta.get_fields()]
                writer.writerow(field_names)  # header

                for obj in qs:
                    row = [
                        getattr(getattr(obj, fn), 'get_repr')()
                        if hasattr(getattr(obj, fn), 'get_repr')
                        else str(getattr(obj, fn))
                        for fn in field_names
                    ]
                    writer.writerow(row)

            csv_files.append(tmp_cvf_name)

        return csv_files

    def __get_csv_name(self, queryset, now, base_dir):
        tmp_cvf_name = os.path.join(
            base_dir,
            f'audit_{now}_{self.archive_model_postfix_map[queryset.model._meta.object_name]}.csv',
        )
        if os.path.exists(tmp_cvf_name):
            os.remove(tmp_cvf_name)

        return tmp_cvf_name

    def __log(self, msg):
        msg = 'Audit cleanup/archiving: ' + str(msg)
        self.stdout.write(msg)
        log.info(msg)
