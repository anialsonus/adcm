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


import logging
from collections import OrderedDict
from typing import Tuple, Union

from django.conf import settings
from django.utils import timezone as tz

from audit.apps import AuditConfig
from audit.models import AuditLog, AuditLogOperationResult, AuditSession

audit_log = logging.getLogger(AuditConfig.name)


class CEFLogConstants:
    cef_version: str = "CEF: 0"
    device_vendor: str = "Arenadata Software"
    device_product: str = "Arenadata Cluster Manager"
    adcm_version: str = settings.ADCM_VERSION
    operation_name_session: str = "User logged"
    extension_keys: Tuple[str] = ("actor", "act", "operation", "resource", "result", "timestamp")
    undefined = "<undefined>"


def cef_logger(
    audit_instance: Union[AuditLog, AuditSession],
    signature_id: str,
    severity: int = 1,
    empty_resource: bool = False,
) -> None:
    extension = OrderedDict.fromkeys(CEFLogConstants.extension_keys, None)
    extension["timestamp"] = str(tz.now())

    if isinstance(audit_instance, AuditSession):
        operation_name = CEFLogConstants.operation_name_session
        if audit_instance.user is not None:
            extension["actor"] = audit_instance.user.username
        else:
            extension["actor"] = audit_instance.login_details.get(
                "username", CEFLogConstants.undefined
            )
        extension["operation"] = operation_name
        extension["result"] = audit_instance.login_result

    elif isinstance(audit_instance, AuditLog):
        operation_name = audit_instance.operation_name
        if audit_instance.user is not None:
            extension["actor"] = audit_instance.user.username
        else:
            extension["actor"] = CEFLogConstants.undefined
        extension["act"] = audit_instance.operation_type
        extension["operation"] = operation_name
        if not empty_resource and audit_instance.audit_object:
            extension["resource"] = audit_instance.audit_object.object_name
        extension["result"] = audit_instance.operation_result
        if audit_instance.operation_result == AuditLogOperationResult.Denied:
            severity = 3

    else:
        raise NotImplementedError

    extension = " ".join([f"{k}={v}" for k, v in extension.items() if v is not None])

    msg = (
        f"{CEFLogConstants.cef_version}|{CEFLogConstants.device_vendor}|"
        f"{CEFLogConstants.device_product}|{CEFLogConstants.adcm_version}|"
        f"{signature_id}|{operation_name}|{severity}|{extension}"
    )

    audit_log.info(msg)
