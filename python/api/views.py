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

import rest_framework
from rest_framework import routers
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

import cm.api
import cm.job
import cm.stack
import cm.status_api
from adcm.settings import ADCM_VERSION


class APIRoot(routers.APIRootView):
    """
    Arenadata Chapel API
    """

    permission_classes = (rest_framework.permissions.AllowAny,)
    api_root_dict = {
        'adcm': 'adcm',
        'cluster': 'cluster',
        'profile': 'profile-list',
        'provider': 'provider',
        'host': 'host',
        'service': 'service',
        'component': 'component',
        'group-config': 'group-config-list',
        'config': 'config-list',
        'config-log': 'config-log-list',
        'job': 'job',
        'stack': 'stack',
        'stats': 'stats',
        'task': 'task',
        'logout': 'logout',
        'info': 'adcm-info',
        'concern': 'concern',
        'rbac': 'rbac:root',
        'token': 'token',
    }


class NameConverter:
    regex = cm.stack.NAME_REGEX

    def to_python(self, value):
        return value

    def to_url(self, value):
        return value


class ADCMInfo(APIView):
    permission_classes = (rest_framework.permissions.AllowAny,)

    def get(self, request):
        """
        General info about ADCM
        """
        return Response({'adcm_version': ADCM_VERSION, 'google_oauth': cm.api.has_google_oauth()})


class ViewInterfaceGenericViewSet(viewsets.GenericViewSet):
    def get_serializer_class(self):
        view = self.request.query_params.get('view', None)
        if view == 'interface':
            return self.ui_serializer_class
        else:
            return self.serializer_class
