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

from django.contrib.contenttypes.models import ContentType
from rest_flex_fields.serializers import FlexFieldsSerializerMixin
from rest_framework import serializers
from rest_framework.reverse import reverse

from cm.errors import AdcmEx
from cm.models import GroupConfig, Host, Cluster, ClusterObject, ServiceComponent, HostProvider


class HostFlexFieldsSerializer(FlexFieldsSerializerMixin, serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = (
            'id',
            'cluster_id',
            'prototype_id',
            'provider_id',
            'config_id',
            'fqdn',
            'state',
        )


def check_object_type(type_name):
    """Object type checking"""
    if type_name not in ['cluster', 'service', 'component', 'provider']:
        raise AdcmEx('GROUP_CONFIG_TYPE_ERROR')


def translate_model_name(model_name):
    """Translating model name to display model name"""
    if model_name == 'clusterobject':
        return 'service'
    elif model_name == 'servicecomponent':
        return 'component'
    elif model_name == 'hostprovider':
        return 'provider'
    else:
        return model_name


def revert_model_name(name):
    """Translating display model name to model name"""
    if name == 'service':
        return 'clusterobject'
    elif name == 'component':
        return 'servicecomponent'
    elif name == 'provider':
        return 'hostprovider'
    else:
        return name


class ObjectTypeField(serializers.Field):
    def to_representation(self, value):
        return translate_model_name(value.model)

    def to_internal_value(self, data):
        check_object_type(data)
        return ContentType.objects.get(app_label='cm', model=revert_model_name(data))


class GroupConfigsHyperlinkedIdentityField(serializers.HyperlinkedIdentityField):
    """Return url for group_configs for Cluster, Provider, Component or Service"""

    def get_url(self, obj, view_name, request, format):  # pylint: disable=redefined-builtin
        url = reverse(viewname=view_name, request=request, format=format)
        return f'{url}?object_id={obj.id}&object_type={obj.prototype.type}'


class HostCandidateHyperlinkedIdentityField(serializers.HyperlinkedIdentityField):
    """Return url for host candidate for group config use action"""

    view_name = 'group-config-host-candidate'

    def get_url(self, obj, view_name, request, format):  # pylint: disable=redefined-builtin
        return reverse(viewname=view_name, args=[obj.pk], request=request, format=format)


class HostCandidateHyperlinkedIdentityFieldAlternative(serializers.HyperlinkedIdentityField):
    """Return url for host candidate for group config use filters"""

    view_name = 'host'

    def get_url(self, obj, view_name, request, format):  # pylint: disable=redefined-builtin
        url = reverse(viewname=view_name, request=request, format=format)
        obj = obj.object
        if isinstance(obj, Cluster):
            query = f'?cluster_id={obj.id}'
        elif isinstance(obj, HostProvider):
            query = f'?provider_id={obj.id}'
        elif isinstance(obj, ClusterObject):
            query = f'?hostcomponent__service_id={obj.id}'
        elif isinstance(obj, ServiceComponent):
            query = f'?hostcomponent_component_id={obj.id}'
        else:
            raise AdcmEx('GROUP_CONFIG_TYPE_ERROR')
        group_config_ids = ','.join(map(str, obj.group_configs.all().values_list('id', flat=True)))
        query = f'{query}&exclude_groupconfig__in={group_config_ids}'
        return f'{url}{query}'


class GroupConfigSerializer(FlexFieldsSerializerMixin, serializers.ModelSerializer):
    object_type = ObjectTypeField()
    url = serializers.HyperlinkedIdentityField(view_name='group-config-detail')
    hosts = serializers.SerializerMethodField()
    config = serializers.HyperlinkedRelatedField(view_name='config-detail', read_only=True)
    host_candidate = HostCandidateHyperlinkedIdentityField(
        view_name=HostCandidateHyperlinkedIdentityField.view_name
    )
    host_candidate_alternative = HostCandidateHyperlinkedIdentityFieldAlternative(
        view_name=HostCandidateHyperlinkedIdentityFieldAlternative.view_name
    )

    class Meta:
        model = GroupConfig
        fields = (
            'id',
            'object_id',
            'object_type',
            'name',
            'description',
            'hosts',
            'config',
            'host_candidate',
            'host_candidate_alternative',
            'url',
        )
        expandable_fields = {
            'hosts': (HostFlexFieldsSerializer, {'many': True}),
            'host_candidate': (HostFlexFieldsSerializer, {'many': True}),
        }

    def get_hosts(self, obj):
        url = reverse(
            viewname='host',
            request=self.context['request'],
            format=self.context.get('format'),
        )
        return f'{url}?groupconfig={obj.id}'
