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

from rest_framework import decorators
from rest_framework import status
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.mixins import CreateModelMixin
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.permissions import IsAuthenticated
from silk.profiling.profiler import silk_profile

import cm.api
import cm.bundle
from api.action.serializers import StackActionSerializer
from api.base_view import (
    GenericUIView,
    DetailView,
    PaginatedView,
    GenericUIViewSet,
    ModelPermOrReadOnlyForAuth,
)
from api.utils import check_obj
from cm.models import Bundle, Prototype, Action
from cm.models import PrototypeConfig, Upgrade, PrototypeExport
from cm.models import PrototypeImport
from . import serializers


class CsrfOffSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return


class UploadBundle(GenericUIView):
    queryset = Bundle.objects.all()
    serializer_class = serializers.UploadBundle
    authentication_classes = (CsrfOffSessionAuthentication, TokenAuthentication)
    parser_classes = (MultiPartParser,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoadBundle(CreateModelMixin, GenericUIViewSet):
    queryset = Prototype.objects.all()
    serializer_class = serializers.LoadBundle

    @decorators.action(methods=['put'], detail=False)
    def servicemap(self, request):
        cm.api.load_service_map()
        return Response(status=status.HTTP_200_OK)

    @silk_profile(name='Upload bundle')
    def create(self, request, *args, **kwargs):
        """
        post:
        Load bundle
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            bundle = cm.bundle.load_bundle(serializer.validated_data.get('bundle_file'))
            srl = serializers.BundleSerializer(bundle, context={'request': request})
            return Response(srl.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BundleList(PaginatedView):
    """
    get:
    List all bundles
    """

    queryset = Bundle.objects.exclude(hash='adcm')
    serializer_class = serializers.BundleSerializer
    permission_classes = (IsAuthenticated,)
    filterset_fields = ('name', 'version')
    ordering_fields = ('name', 'version_order')


class BundleDetail(DetailView):
    """
    get:
    Show bundle

    delete:
    Remove bundle
    """

    queryset = Bundle.objects.all()
    serializer_class = serializers.BundleSerializer
    permission_classes = (ModelPermOrReadOnlyForAuth,)
    lookup_field = 'id'
    lookup_url_kwarg = 'bundle_id'
    error_code = 'BUNDLE_NOT_FOUND'

    def delete(self, request, bundle_id):
        bundle = check_obj(Bundle, bundle_id, 'BUNDLE_NOT_FOUND')
        cm.bundle.delete_bundle(bundle)
        return Response(status=status.HTTP_204_NO_CONTENT)


class BundleUpdate(GenericUIView):
    queryset = Bundle.objects.all()
    serializer_class = serializers.BundleSerializer

    def put(self, request, bundle_id):
        """
        update bundle
        """
        bundle = check_obj(Bundle, bundle_id, 'BUNDLE_NOT_FOUND')
        cm.bundle.update_bundle(bundle)
        serializer = self.get_serializer(bundle)
        return Response(serializer.data)


class BundleLicense(GenericUIView):
    action = 'retrieve'
    queryset = Bundle.objects.all()
    serializer_class = serializers.LicenseSerializer

    def get(self, request, bundle_id):
        bundle = check_obj(Bundle, bundle_id, 'BUNDLE_NOT_FOUND')
        body = cm.api.get_license(bundle)
        url = reverse('accept-license', kwargs={'bundle_id': bundle.id}, request=request)
        return Response({'license': bundle.license, 'accept': url, 'text': body})


class AcceptLicense(GenericUIView):
    queryset = Bundle.objects.all()
    serializer_class = serializers.LicenseSerializer

    def put(self, request, bundle_id):
        bundle = check_obj(Bundle, bundle_id, 'BUNDLE_NOT_FOUND')
        cm.api.accept_license(bundle)
        return Response(status=status.HTTP_200_OK)


class PrototypeList(PaginatedView):
    """
    get:
    List all stack prototypes
    """

    queryset = Prototype.objects.all()
    serializer_class = serializers.PrototypeSerializer
    filterset_fields = ('name', 'bundle_id', 'type')
    ordering_fields = ('display_name', 'version_order')


class ServiceList(PaginatedView):
    """
    get:
    List all stack services
    """

    queryset = Prototype.objects.filter(type='service')
    serializer_class = serializers.ServiceSerializer
    filterset_fields = ('name', 'bundle_id')
    ordering_fields = ('display_name', 'version_order')


class ServiceDetail(DetailView):
    """
    get:
    Show stack service
    """

    queryset = Prototype.objects.filter(type='service')
    serializer_class = serializers.ServiceDetailSerializer
    lookup_field = 'id'
    lookup_url_kwarg = 'prototype_id'
    error_code = 'SERVICE_NOT_FOUND'

    def get_object(self):
        service = super().get_object()
        service.actions = Action.objects.filter(prototype__type='service', prototype__id=service.id)
        service.components = Prototype.objects.filter(parent=service, type='component')
        service.config = PrototypeConfig.objects.filter(prototype=service, action=None).order_by(
            'id'
        )
        service.exports = PrototypeExport.objects.filter(prototype=service)
        service.imports = PrototypeImport.objects.filter(prototype=service)
        return service


class ProtoActionDetail(GenericUIView):
    queryset = Action.objects.all()
    serializer_class = StackActionSerializer

    def get(self, request, action_id):
        """
        Show action
        """
        obj = check_obj(Action, action_id, 'ACTION_NOT_FOUND')
        serializer = self.get_serializer(obj)
        return Response(serializer.data)


class ServiceProtoActionList(GenericUIView):
    queryset = Action.objects.filter(prototype__type='service')
    serializer_class = StackActionSerializer

    def get(self, request, prototype_id):
        """
        List all actions of a specified service
        """
        obj = self.get_queryset().filter(prototype_id=prototype_id)
        serializer = self.get_serializer(obj, many=True)
        return Response(serializer.data)


class ComponentList(PaginatedView):
    """
    get:
    List all stack components
    """

    queryset = Prototype.objects.filter(type='component')
    serializer_class = serializers.ComponentTypeSerializer
    filterset_fields = ('name', 'bundle_id')
    ordering_fields = ('display_name', 'version_order')


class HostTypeList(PaginatedView):
    """
    get:
    List all host types
    """

    queryset = Prototype.objects.filter(type='host')
    serializer_class = serializers.HostTypeSerializer
    filterset_fields = ('name', 'bundle_id')
    ordering_fields = ('display_name', 'version_order')


class ProviderTypeList(PaginatedView):
    """
    get:
    List all host providers types
    """

    queryset = Prototype.objects.filter(type='provider')
    serializer_class = serializers.ProviderTypeSerializer
    filterset_fields = ('name', 'bundle_id', 'display_name')
    ordering_fields = ('display_name', 'version_order')


class ClusterTypeList(PaginatedView):
    """
    get:
    List all cluster types
    """

    queryset = Prototype.objects.filter(type='cluster')
    serializer_class = serializers.ClusterTypeSerializer
    filterset_fields = ('name', 'bundle_id', 'display_name')
    ordering_fields = ('display_name', 'version_order')


class AdcmTypeList(GenericUIView):
    """
    get:
    List adcm root object prototypes
    """

    queryset = Prototype.objects.filter(type='adcm')
    serializer_class = serializers.AdcmTypeSerializer
    filterset_fields = ('bundle_id',)

    def get(self, request, *args, **kwargs):
        obj = self.get_queryset()
        serializer = self.get_serializer(obj, many=True)
        return Response(serializer.data)


class AbstractPrototypeDetail(DetailView):
    """Common base class for *PrototypeDetail"""

    lookup_field = 'id'
    lookup_url_kwarg = 'prototype_id'
    error_code = 'PROTOTYPE_NOT_FOUND'

    def get_object(self):
        obj_type = super().get_object()
        act_set = []
        for action in Action.objects.filter(prototype__id=obj_type.id):
            action.config = PrototypeConfig.objects.filter(prototype__id=obj_type.id, action=action)
            act_set.append(action)
        obj_type.actions = act_set
        obj_type.config = PrototypeConfig.objects.filter(prototype=obj_type, action=None)
        obj_type.imports = PrototypeImport.objects.filter(prototype=obj_type)
        obj_type.exports = PrototypeExport.objects.filter(prototype=obj_type)
        obj_type.upgrade = Upgrade.objects.filter(bundle=obj_type.bundle)
        return obj_type


class PrototypeDetail(AbstractPrototypeDetail):
    """
    get:
    Show prototype
    """

    queryset = Prototype.objects.all()
    serializer_class = serializers.PrototypeDetailSerializer


class AdcmTypeDetail(AbstractPrototypeDetail):
    """
    get:
    Show adcm prototype
    """

    queryset = Prototype.objects.filter(type='adcm')
    serializer_class = serializers.AdcmTypeDetailSerializer


class ClusterTypeDetail(AbstractPrototypeDetail):
    """
    get:
    Show cluster prototype
    """

    queryset = Prototype.objects.filter(type='cluster')
    serializer_class = serializers.ClusterTypeDetailSerializer


class ComponentTypeDetail(AbstractPrototypeDetail):
    """
    get:
    Show component prototype
    """

    queryset = Prototype.objects.filter(type='component')
    serializer_class = serializers.ComponentTypeDetailSerializer


class HostTypeDetail(AbstractPrototypeDetail):
    """
    get:
    Show host prototype
    """

    queryset = Prototype.objects.filter(type='host')
    serializer_class = serializers.HostTypeDetailSerializer


class ProviderTypeDetail(AbstractPrototypeDetail):
    """
    get:
    Show host provider prototype
    """

    queryset = Prototype.objects.filter(type='provider')
    serializer_class = serializers.ProviderTypeDetailSerializer
