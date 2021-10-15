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

from django_filters import rest_framework as drf_filters
from rest_framework import status
from rest_framework.response import Response

from api.api_views import PageView, DetailViewDelete, create, check_obj
from cm.api import remove_host_from_cluster, delete_host
from cm.errors import AdcmEx
from cm.models import Cluster, HostProvider, Host, GroupConfig, ClusterObject, ServiceComponent
from . import serializers


class NumberInFilter(drf_filters.BaseInFilter, drf_filters.NumberFilter):
    pass


class HostFilter(drf_filters.FilterSet):
    cluster_is_null = drf_filters.BooleanFilter(field_name='cluster_id', lookup_expr='isnull')
    provider_is_null = drf_filters.BooleanFilter(field_name='provider_id', lookup_expr='isnull')
    group_config = drf_filters.ModelChoiceFilter(
        queryset=GroupConfig.objects.all(), field_name='group_config', label='GroupConfig'
    )
    hostcomponent__service_id = drf_filters.ModelChoiceFilter(
        queryset=ClusterObject.objects.all(),
        field_name='hostcomponent__service_id',
        label='HostComponentService',
        distinct=True,
    )
    hostcomponent__component_id = drf_filters.ModelChoiceFilter(
        queryset=ServiceComponent.objects.all(),
        field_name='hostcomponent__component_id',
        label='HostComponentComponent',
        distinct=True,
    )

    exclude_group_config__in = NumberInFilter(
        field_name='group_config', lookup_expr='in', label='ExcludeGroupConfigIn', exclude=True
    )

    class Meta:
        model = Host
        fields = [
            'cluster_id',
            'prototype_id',
            'provider_id',
            'fqdn',
            'cluster_is_null',
            'provider_is_null',
            'group_config',
            'hostcomponent__service_id',
            'hostcomponent__component_id',
            'exclude_group_config__in',
        ]


class HostList(PageView):
    """
    get:
    List all hosts

    post:
    Create new host
    """

    queryset = Host.objects.all()
    serializer_class = serializers.HostSerializer
    serializer_class_ui = serializers.HostUISerializer
    filterset_class = HostFilter
    filterset_fields = (
        'cluster_id',
        'prototype_id',
        'provider_id',
        'fqdn',
        'cluster_is_null',
        'provider_is_null',
        'group_config',
        'hostcomponent__service_id',
        'hostcomponent__component_id',
        'exclude_group_config__in',
    )  # just for documentation
    ordering_fields = (
        'fqdn',
        'state',
        'provider__name',
        'cluster__name',
        'prototype__display_name',
        'prototype__version_order',
    )

    def get(self, request, *args, **kwargs):
        """
        List all hosts
        """
        queryset = self.get_queryset()
        if 'cluster_id' in kwargs:  # List cluster hosts
            cluster = check_obj(Cluster, kwargs['cluster_id'])
            queryset = self.get_queryset().filter(cluster=cluster)
        if 'provider_id' in kwargs:  # List provider hosts
            provider = check_obj(HostProvider, kwargs['provider_id'])
            queryset = self.get_queryset().filter(provider=provider)
        return self.get_page(self.filter_queryset(queryset), request)

    def post(self, request, *args, **kwargs):
        """
        Create host
        """
        serializer = self.serializer_class(
            data=request.data,
            context={
                'request': request,
                'cluster_id': kwargs.get('cluster_id', None),
                'provider_id': kwargs.get('provider_id', None),
            },
        )
        return create(serializer)


class HostListProvider(HostList):
    serializer_class = serializers.ProvideHostSerializer


class HostListCluster(HostList):
    serializer_class = serializers.ClusterHostSerializer


def check_host(host, cluster):
    if host.cluster != cluster:
        msg = f"Host #{host.id} doesn't belong to cluster #{cluster.id}"
        raise AdcmEx('FOREIGN_HOST', msg)


class HostDetail(DetailViewDelete):
    """
    get:
    Show host
    """

    queryset = Host.objects.all()
    serializer_class = serializers.HostDetailSerializer
    serializer_class_ui = serializers.HostUISerializer
    lookup_field = 'id'
    lookup_url_kwarg = 'host_id'
    error_code = 'HOST_NOT_FOUND'

    def get(self, request, host_id, **kwargs):  # pylint: disable=arguments-differ)
        host = check_obj(Host, host_id)
        if 'cluster_id' in kwargs:
            cluster = check_obj(Cluster, kwargs['cluster_id'])
            check_host(host, cluster)
        serial_class = self.select_serializer(request)
        serializer = serial_class(host, context={'request': request})
        return Response(serializer.data)

    def delete(self, request, host_id, **kwargs):  # pylint: disable=arguments-differ
        """
        Delete host
        """
        host = check_obj(Host, host_id, 'HOST_NOT_FOUND')
        if 'cluster_id' in kwargs:
            # Remove host from cluster
            cluster = check_obj(Cluster, kwargs['cluster_id'])
            check_host(host, cluster)
            remove_host_from_cluster(host)
        else:
            # Delete host (and all corresponding host services:components)
            delete_host(host)
        return Response(status=status.HTTP_204_NO_CONTENT)
