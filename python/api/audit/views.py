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

from api.audit.filters import AuditLoginListFilter, AuditOperationListFilter
from api.audit.serializers import AuditLogSerializer, AuditSessionSerializer
from api.utils import SuperuserOnlyMixin
from audit.models import AuditLog, AuditSession
from rest_framework.viewsets import ReadOnlyModelViewSet


# pylint: disable=too-many-ancestors
class AuditOperationViewSet(SuperuserOnlyMixin, ReadOnlyModelViewSet):
    queryset = AuditLog.objects.select_related('audit_object', 'user').order_by(
        '-operation_time', '-pk'
    )
    model_class = AuditLog
    serializer_class = AuditLogSerializer
    filterset_class = AuditOperationListFilter


# pylint: disable=too-many-ancestors
class AuditLoginViewSet(SuperuserOnlyMixin, ReadOnlyModelViewSet):
    queryset = AuditSession.objects.select_related('user').order_by('-login_time', '-pk')
    model_class = AuditSession
    serializer_class = AuditSessionSerializer
    filterset_class = AuditLoginListFilter
