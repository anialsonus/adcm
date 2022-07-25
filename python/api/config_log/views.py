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

from api.base_view import GenericUIViewSet
from api.config.views import check_config_perm
from api.config_log.serializers import ConfigLogSerializer, UIConfigLogSerializer
from audit.utils import audit
from cm.models import ConfigLog
from django.contrib.contenttypes.models import ContentType
from guardian.mixins import PermissionListMixin
from rest_framework import status
from rest_framework.mixins import CreateModelMixin, ListModelMixin, RetrieveModelMixin
from rest_framework.permissions import DjangoObjectPermissions
from rest_framework.response import Response


class ConfigLogViewSet(  # pylint: disable=too-many-ancestors
    PermissionListMixin, CreateModelMixin, ListModelMixin, RetrieveModelMixin, GenericUIViewSet
):
    queryset = ConfigLog.objects.all()
    serializer_class = ConfigLogSerializer
    permission_classes = (DjangoObjectPermissions,)
    serializer_class_ui = UIConfigLogSerializer
    permission_required = ['cm.view_configlog']
    filterset_fields = ('id', 'obj_ref')
    ordering_fields = ('id',)

    def get_queryset(self, *args, **kwargs):
        if self.request.user.has_perm('cm.view_settings_of_adcm'):
            return super().get_queryset(*args, **kwargs) | ConfigLog.objects.filter(
                obj_ref__adcm__isnull=False
            )
        else:
            return super().get_queryset(*args, **kwargs).filter(obj_ref__adcm__isnull=True)

    @audit
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # check custom permissions
        obj = serializer.validated_data['obj_ref'].object
        object_type = ContentType.objects.get_for_model(obj).model
        check_config_perm(request.user, 'change', object_type, obj)

        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
