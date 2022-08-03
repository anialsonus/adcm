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

from dataclasses import dataclass

from django.contrib.auth.models import User
from django.db import models


class AuditObjectType(models.TextChoices):
    Cluster = "cluster", "cluster"
    Service = "service", "service"
    Component = "component", "component"
    Host = "host", "host"
    Provider = "provider", "provider"
    Bundle = "bundle", "bundle"
    ADCM = "adcm", "adcm"
    User = "user", "user"
    Group = "group", "group"
    Role = "role", "role"
    Policy = "policy", "policy"


class AuditLogOperationType(models.TextChoices):
    Create = "create", "create"
    Update = "update", "update"
    Delete = "delete", "delete"


class AuditLogOperationResult(models.TextChoices):
    Success = "success", "success"
    Fail = "fail", "fail"
    Denied = "denied", "denied"


class AuditSessionLoginResult(models.TextChoices):
    Success = "success", "success"
    WrongPassword = "wrong_password", "wrong_password"
    AccountDisabled = "account_disabled", "account_disabled"
    UserNotFound = "user_not_found", "user_not_found"


class AuditObject(models.Model):
    object_id = models.PositiveIntegerField()
    object_name = models.CharField(max_length=160)
    object_type = models.CharField(max_length=16, choices=AuditObjectType.choices)
    is_deleted = models.BooleanField(default=False)

    def get_repr(self):
        return (
            f'<{self.__class__.__name__} #{self.pk}: {self.object_type} '
            f'#{self.object_id} {self.object_name}, deleted: {self.is_deleted}>'
        )


class AuditLog(models.Model):
    audit_object = models.ForeignKey(AuditObject, on_delete=models.CASCADE, null=True)
    operation_name = models.CharField(max_length=160)
    operation_type = models.CharField(max_length=16, choices=AuditLogOperationType.choices)
    operation_result = models.CharField(max_length=16, choices=AuditLogOperationResult.choices)
    operation_time = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    object_changes = models.JSONField(default=dict)


class AuditSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    login_result = models.CharField(max_length=64, choices=AuditSessionLoginResult.choices)
    login_time = models.DateTimeField(auto_now_add=True)
    login_details = models.JSONField(default=dict)


@dataclass
class AuditOperation:
    name: str
    operation_type: str
