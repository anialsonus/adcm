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

from adcm.permissions import (
    ADD_SERVICE_PERM,
    CHANGE_MM_PERM,
    VIEW_CLUSTER_PERM,
    VIEW_SERVICE_PERM,
    ChangeMMPermissions,
    check_custom_perm,
    get_object_for_user,
)
from audit.utils import audit
from cm.errors import AdcmEx
from cm.models import ADCMEntityStatus, Cluster, ClusterObject
from cm.services.maintenance_mode import get_maintenance_mode_response
from cm.services.service import delete_service_from_api
from cm.services.status.notify import update_mm_objects
from django_filters.rest_framework.backends import DjangoFilterBackend
from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from guardian.mixins import PermissionListMixin
from rest_framework.decorators import action
from rest_framework.mixins import (
    CreateModelMixin,
    DestroyModelMixin,
    ListModelMixin,
    RetrieveModelMixin,
)
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_204_NO_CONTENT,
    HTTP_400_BAD_REQUEST,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
)

from api_v2.api_schema import DefaultParams, ErrorSerializer
from api_v2.config.utils import ConfigSchemaMixin
from api_v2.service.filters import ServiceFilter
from api_v2.service.permissions import ServicePermissions
from api_v2.service.serializers import (
    ServiceCreateSerializer,
    ServiceMaintenanceModeSerializer,
    ServiceRetrieveSerializer,
    ServiceStatusSerializer,
)
from api_v2.service.utils import (
    bulk_add_services_to_cluster,
    validate_service_prototypes,
)
from api_v2.views import ADCMGenericViewSet, ObjectWithStatusViewMixin


@extend_schema_view(
    retrieve=extend_schema(
        operation_id="getClusterService",
        summary="GET cluster service",
        description="Get information about a specific cluster service.",
        responses={
            HTTP_200_OK: ServiceRetrieveSerializer,
            HTTP_403_FORBIDDEN: ErrorSerializer,
            HTTP_404_NOT_FOUND: ErrorSerializer,
        },
    ),
    list=extend_schema(
        operation_id="getClusterServices",
        summary="GET cluster services",
        description="Get a list of all services of a particular cluster with information on them.",
        parameters=[
            DefaultParams.LIMIT,
            DefaultParams.OFFSET,
            DefaultParams.ordering_by("Display name"),
            OpenApiParameter(
                name="name",
                location=OpenApiParameter.QUERY,
                description="Case insensitive and partial filter by service name.",
                type=str,
            ),
            OpenApiParameter(
                name="display_name",
                location=OpenApiParameter.QUERY,
                description="Case insensitive and partial filter by service displayName.",
                type=str,
            ),
            OpenApiParameter(
                name="status",
                location=OpenApiParameter.QUERY,
                description="Filter by service status.",
                enum=ADCMEntityStatus.values,
                type=str,
            ),
        ],
        responses={HTTP_200_OK: ServiceRetrieveSerializer(many=True), HTTP_404_NOT_FOUND: ErrorSerializer},
    ),
    create=extend_schema(
        operation_id="postClusterServices",
        summary="POST cluster services",
        description="Add a new cluster services.",
        responses={
            HTTP_201_CREATED: ServiceRetrieveSerializer,
            HTTP_400_BAD_REQUEST: ErrorSerializer,
            HTTP_404_NOT_FOUND: ErrorSerializer,
            HTTP_403_FORBIDDEN: ErrorSerializer,
            HTTP_409_CONFLICT: ErrorSerializer,
        },
    ),
    destroy=extend_schema(
        operation_id="deleteClusterService",
        summary="DELETE cluster service",
        description="Delete a specific cluster service.",
        responses={
            HTTP_204_NO_CONTENT: None,
            HTTP_400_BAD_REQUEST: ErrorSerializer,
            HTTP_403_FORBIDDEN: ErrorSerializer,
            HTTP_404_NOT_FOUND: ErrorSerializer,
            HTTP_409_CONFLICT: ErrorSerializer,
        },
    ),
    maintenance_mode=extend_schema(
        operation_id="postServiceMaintenanceMode",
        summary="POST service maintenance-mode",
        description="Turn on/off maintenance mode on the service.",
        responses={
            HTTP_200_OK: ServiceMaintenanceModeSerializer,
            HTTP_400_BAD_REQUEST: ErrorSerializer,
            HTTP_403_FORBIDDEN: ErrorSerializer,
            HTTP_404_NOT_FOUND: ErrorSerializer,
            HTTP_409_CONFLICT: ErrorSerializer,
        },
    ),
    statuses=extend_schema(
        operation_id="getServiceComponentStatuses",
        summary="GET service component statuses",
        description="Get information about service component statuses.",
        responses={
            HTTP_200_OK: ServiceStatusSerializer,
            HTTP_403_FORBIDDEN: ErrorSerializer,
            HTTP_404_NOT_FOUND: ErrorSerializer,
        },
        parameters=[
            OpenApiParameter(
                name="status",
                required=True,
                location=OpenApiParameter.QUERY,
                description="Case insensitive and partial filter by status.",
                type=str,
            ),
            OpenApiParameter(
                name="clusterId",
                required=True,
                location=OpenApiParameter.PATH,
                description="Cluster id.",
                type=int,
            ),
            OpenApiParameter(
                name="serviceId",
                required=True,
                location=OpenApiParameter.PATH,
                description="Service id.",
                type=int,
            ),
        ],
    ),
)
class ServiceViewSet(
    PermissionListMixin,
    ConfigSchemaMixin,
    CreateModelMixin,
    DestroyModelMixin,
    ListModelMixin,
    RetrieveModelMixin,
    ObjectWithStatusViewMixin,
    ADCMGenericViewSet,
):
    queryset = ClusterObject.objects.select_related("cluster").order_by("pk")
    filterset_class = ServiceFilter
    filter_backends = (DjangoFilterBackend,)
    permission_required = [VIEW_SERVICE_PERM]
    permission_classes = [ServicePermissions]
    audit_model_hint = ClusterObject
    retrieve_status_map_actions = ("list", "statuses")

    def get_queryset(self, *args, **kwargs):
        cluster = get_object_for_user(
            user=self.request.user, perms=VIEW_CLUSTER_PERM, klass=Cluster, id=self.kwargs["cluster_pk"]
        )

        return super().get_queryset(*args, **kwargs).filter(cluster=cluster)

    def get_serializer_class(self):
        match self.action:
            case "create":
                return ServiceCreateSerializer
            case "maintenance_mode":
                return ServiceMaintenanceModeSerializer

        return ServiceRetrieveSerializer

    @audit
    def create(self, request: Request, *args, **kwargs):  # noqa: ARG002
        cluster = get_object_for_user(
            user=request.user, perms=VIEW_CLUSTER_PERM, klass=Cluster, pk=kwargs["cluster_pk"]
        )
        check_custom_perm(user=request.user, action_type=ADD_SERVICE_PERM, model=Cluster.__name__.lower(), obj=cluster)

        multiple_services = isinstance(request.data, list)
        serializer = self.get_serializer(data=request.data, many=multiple_services, context={"cluster": cluster})
        serializer.is_valid(raise_exception=True)

        service_prototypes, error = validate_service_prototypes(
            cluster=cluster, data=serializer.validated_data if multiple_services else [serializer.validated_data]
        )
        if error is not None:
            raise error
        added_services = bulk_add_services_to_cluster(cluster=cluster, prototypes=service_prototypes)

        context = self.get_serializer_context()

        if multiple_services:
            return Response(
                status=HTTP_201_CREATED,
                data=ServiceRetrieveSerializer(instance=added_services, many=True, context=context).data,
            )

        return Response(
            status=HTTP_201_CREATED,
            data=ServiceRetrieveSerializer(instance=added_services[0], context=context).data,
        )

    @audit
    def destroy(self, request: Request, *args, **kwargs):  # noqa: ARG002
        instance = self.get_object()
        return delete_service_from_api(service=instance)

    @audit
    @update_mm_objects
    @action(methods=["post"], detail=True, url_path="maintenance-mode", permission_classes=[ChangeMMPermissions])
    def maintenance_mode(self, request: Request, *args, **kwargs) -> Response:  # noqa: ARG002
        service: ClusterObject = get_object_for_user(
            user=request.user, perms=VIEW_SERVICE_PERM, klass=ClusterObject, pk=kwargs["pk"]
        )

        if not service.is_maintenance_mode_available:
            raise AdcmEx(code="MAINTENANCE_MODE_NOT_AVAILABLE", msg="Service does not support maintenance mode")

        check_custom_perm(
            user=request.user, action_type=CHANGE_MM_PERM, model=service.__class__.__name__.lower(), obj=service
        )

        serializer = self.get_serializer_class()(instance=service, data=request.data)
        serializer.is_valid(raise_exception=True)

        response: Response = get_maintenance_mode_response(obj=self.get_object(), serializer=serializer)
        if response.status_code == HTTP_200_OK:
            response.data = serializer.data

        return response

    @action(methods=["get"], detail=True, url_path="statuses")
    def statuses(self, request: Request, *args, **kwargs) -> Response:  # noqa: ARG002
        service = get_object_for_user(user=request.user, perms=VIEW_SERVICE_PERM, klass=ClusterObject, id=kwargs["pk"])

        return Response(data=ServiceStatusSerializer(instance=service, context=self.get_serializer_context()).data)
