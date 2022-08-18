from datetime import datetime, timedelta

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from audit.models import AuditLog, AuditLogOperationType, AuditLogOperationResult
from cm.models import (
    ADCM,
    Bundle,
    Cluster,
    ConfigLog,
    JobLog,
    ObjectConfig,
    Prototype,
    TaskLog,
)
from rbac.models import User


class TestLogrotate(TestCase):
    def setUp(self) -> None:
        super().setUp()

        bundle = Bundle.objects.create()
        date = timezone.now() - timedelta(days=3)
        prototype = Prototype.objects.create(bundle=bundle, type="adcm")
        config = ObjectConfig.objects.create(current=1, previous=0)
        ConfigLog.objects.create(
            obj_ref=config,
            config={
                "job_log": {"log_rotation_on_fs": 1, "log_rotation_in_db": 1},
                "config_rotation": {"config_rotation_in_db": 1},
                "logrotate": {"size": "10M", "max_history": 10, "compress": False},
            },
            attr={"logrotate": {"active": False}},
        )
        ADCM.objects.create(prototype=prototype, name="ADCM", config=config)
        self.user = User.objects.create_superuser("system", "", None, built_in=True)
        prototype = Prototype.objects.create(bundle=bundle, type="cluster")
        config_2 = ObjectConfig.objects.create(current=4, previous=3)
        cluster = Cluster.objects.create(name="test_cluster", prototype=prototype, config=config_2)
        TaskLog.objects.create(
            object_id=cluster.id, start_date=date, finish_date=date, status="success"
        )
        JobLog.objects.create(start_date=date, finish_date=date)
        ConfigLog.objects.create(obj_ref=config_2)
        ConfigLog.objects.all().update(date=date)

    def check_auditlog(self, log: AuditLog, name):
        self.assertIsNone(log.audit_object)
        self.assertEqual(log.operation_name, name)
        self.assertEqual(log.operation_type, AuditLogOperationType.Delete)
        self.assertEqual(log.operation_result, AuditLogOperationResult.Success)
        assert isinstance(log.operation_time, datetime)
        self.assertEqual(log.user.pk, self.user.pk)

    def test_logrotate(
        self,
    ):
        call_command("logrotate", "--target=all")
        logs: AuditLog = AuditLog.objects.order_by("operation_time")
        self.assertEqual(logs.count(), 4)
        self.check_auditlog(logs[0], "\"Task log cleanup on schedule\" job launched")
        self.check_auditlog(logs[1], "\"Task log cleanup on schedule\" job completed")
        self.check_auditlog(logs[2], "\"Objects configurations cleanup on schedule\" job launched")
        self.check_auditlog(logs[3], "\"Objects configurations cleanup on schedule\" job completed")
        call_command("logrotate", "--target=all")
        new_logs = AuditLog.objects.order_by("operation_time")
        self.assertEqual(new_logs.count(), 4)
