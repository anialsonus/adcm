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

from functools import partial

from audit.models import MODEL_TO_AUDIT_OBJECT_TYPE_MAP, AuditObject
from django.db.models.signals import pre_delete, pre_save
from django.db.transaction import on_commit
from django.dispatch import receiver
from rbac.models import Group, Policy

from cm.models import Cluster, ConcernItem, Host
from cm.status_api import send_concern_delete_event


@receiver(signal=pre_save, sender=Cluster)
@receiver(signal=pre_save, sender=Group)
@receiver(signal=pre_save, sender=Policy)
def rename_audit_object(sender, instance, **kwargs) -> None:
    if kwargs["raw"]:
        return

    if instance.pk and sender.objects.get(pk=instance.pk).name == instance.name:
        return

    audit_obj = AuditObject.objects.filter(
        object_id=instance.pk,
        object_type=MODEL_TO_AUDIT_OBJECT_TYPE_MAP[sender],
    ).first()
    if not audit_obj:
        return

    audit_obj.object_name = instance.name
    audit_obj.save(update_fields=["object_name"])


@receiver(signal=pre_save, sender=Host)
def rename_audit_object_host(sender, instance, **kwargs) -> None:
    if kwargs["raw"]:
        return

    if instance.pk and sender.objects.get(pk=instance.pk).fqdn == instance.fqdn:
        return

    audit_obj = AuditObject.objects.filter(
        object_id=instance.pk,
        object_type=MODEL_TO_AUDIT_OBJECT_TYPE_MAP[sender],
    ).first()
    if not audit_obj:
        return

    audit_obj.object_name = instance.fqdn
    audit_obj.save(update_fields=["object_name"])


@receiver(signal=pre_delete, sender=ConcernItem)
def send_delete_event(sender, instance: ConcernItem, **kwargs):  # noqa: ARG001
    # This is "sort of" optimization, not sure if there's a lot of profit in sending all these stuff anyway.
    # Also, probably it'll be better to collect all data for send and then pass closure func looping over those values:
    # that way there won't be much of a queue for on commit => fewer objects => less memory => less processing.
    for qs in instance.related_querysets:
        for object_id, object_type in qs.values_list("id", "prototype__type"):
            on_commit(
                func=partial(
                    send_concern_delete_event,
                    object_id=object_id,
                    object_type=object_type,
                    concern_id=instance.pk,
                )
            )
