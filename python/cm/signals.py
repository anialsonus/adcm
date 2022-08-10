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

from audit.models import AUDIT_OBJECT_TYPE_TO_MODEL_MAP
from audit.utils import mark_deleted_audit_object
from cm.models import (
    ADCM,
    Bundle,
    Cluster,
    ClusterObject,
    Host,
    HostProvider,
    ServiceComponent,
)
from django.db.models.signals import post_delete
from django.dispatch import receiver


@receiver(post_delete, sender=Cluster)
@receiver(post_delete, sender=ClusterObject)
@receiver(post_delete, sender=ServiceComponent)
@receiver(post_delete, sender=Host)
@receiver(post_delete, sender=HostProvider)
@receiver(post_delete, sender=Bundle)
@receiver(post_delete, sender=ADCM)
def mark_deleted_audit_object_handler(sender, instance, **kwargs):
    mark_deleted_audit_object(instance=instance, object_type=AUDIT_OBJECT_TYPE_TO_MODEL_MAP[sender])
