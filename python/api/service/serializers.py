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

# pylint: disable=redefined-builtin

from django.db.utils import IntegrityError
from rest_framework import serializers
from rest_framework.reverse import reverse

from api.api_views import check_obj, filter_actions, CommonAPIURL
from api.cluster_serial import BindSerializer
from api.action.serializers import ActionShort
from api.component.serializers import ComponentUISerializer

from cm import issue
from cm import status_api
from cm.api import add_service_to_cluster, multi_bind, bind
from cm.errors import AdcmApiEx, AdcmEx
from cm.models import Prototype, Action, ServiceComponent, Cluster


class ServiceObjectUrlField(serializers.HyperlinkedIdentityField):
    def get_url(self, obj, view_name, request, format):
        kwargs = {'service_id': obj.id}
        return reverse(view_name, kwargs=kwargs, request=request, format=format)


class ServiceComponentDetailsUrlField(serializers.HyperlinkedIdentityField):
    def get_url(self, obj, view_name, request, format):
        kwargs = {'service_id': obj.service.id, 'component_id': obj.id}
        return reverse(view_name, kwargs=kwargs, request=request, format=format)


class ServiceActionDetailsUrlField(serializers.HyperlinkedIdentityField):
    def get_url(self, obj, view_name, request, format):
        kwargs = {'service_id': self.context['service_id'], 'action_id': obj.id}
        return reverse(view_name, kwargs=kwargs, request=request, format=format)


class ServiceSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    cluster_id = serializers.IntegerField(required=True)
    name = serializers.CharField(read_only=True)
    display_name = serializers.CharField(read_only=True)
    state = serializers.CharField(read_only=True)
    prototype_id = serializers.IntegerField(required=True, help_text='id of service prototype')
    url = ServiceObjectUrlField(read_only=True, view_name='service-details')

    def validate_prototype_id(self, prototype_id):
        prototype = check_obj(
            Prototype, {'id': prototype_id, 'type': 'service'}, 'PROTOTYPE_NOT_FOUND')
        return prototype

    def create(self, validated_data):
        try:
            cluster = check_obj(
                Cluster, {'id': validated_data['cluster_id']}, 'CLUSTER_NOT_FOUND')
            prototype = check_obj(
                Prototype, {'id': validated_data['prototype_id']}, 'PROTOTYPE_NOT_FOUND')
            return add_service_to_cluster(cluster, prototype)
        except IntegrityError:
            raise AdcmApiEx('SERVICE_CONFLICT') from None
        except AdcmEx as e:
            raise AdcmApiEx(e.code, e.msg, e.http_code) from e


class ServiceDetailSerializer(ServiceSerializer):
    prototype_id = serializers.IntegerField(read_only=True)
    description = serializers.CharField(read_only=True)
    bundle_id = serializers.IntegerField(read_only=True)
    issue = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    monitoring = serializers.CharField(read_only=True)
    action = CommonAPIURL(read_only=True, view_name='object-action')
    config = CommonAPIURL(read_only=True, view_name='object-config')
    component = ServiceObjectUrlField(read_only=True, view_name='component')
    imports = ServiceObjectUrlField(read_only=True, view_name='service-import')
    bind = ServiceObjectUrlField(read_only=True, view_name='service-bind')
    prototype = serializers.HyperlinkedIdentityField(
        view_name='service-type-details', lookup_field='prototype_id',
        lookup_url_kwarg='prototype_id')

    def get_issue(self, obj):
        return issue.get_issue(obj)

    def get_status(self, obj):
        return status_api.get_service_status(obj.cluster.id, obj.id)


class ServiceUISerializer(ServiceDetailSerializer):
    actions = serializers.SerializerMethodField()
    components = serializers.SerializerMethodField()
    name = serializers.CharField(read_only=True)
    version = serializers.SerializerMethodField()
    action = CommonAPIURL(view_name='object-action')
    config = CommonAPIURL(view_name='object-config')

    def get_actions(self, obj):
        act_set = Action.objects.filter(prototype=obj.prototype)
        self.context['object'] = obj
        self.context['service_id'] = obj.id
        actions = filter_actions(obj, act_set)
        acts = ActionShort(actions, many=True, context=self.context)
        return acts.data

    def get_components(self, obj):
        comps = ServiceComponent.objects.filter(service=obj, cluster=obj.cluster)
        return ComponentUISerializer(comps, many=True, context=self.context).data

    def get_version(self, obj):
        return obj.prototype.version


class ServiceComponentUrlField(serializers.HyperlinkedIdentityField):
    def get_url(self, obj, view_name, request, format):
        kwargs = {'service_id': obj.service.id, 'component_id': obj.id}
        return reverse(view_name, kwargs=kwargs, request=request, format=format)


class ImportPostSerializer(serializers.Serializer):
    bind = serializers.JSONField()

    def create(self, validated_data):
        try:
            binds = validated_data.get('bind')
            service = self.context.get('service')
            cluster = self.context.get('cluster')
            return multi_bind(cluster, service, binds)
        except AdcmEx as error:
            raise AdcmApiEx(error.code, error.msg, error.http_code, error.adds) from error


class ServiceBindUrlFiels(serializers.HyperlinkedIdentityField):
    def get_url(self, obj, view_name, request, format):
        kwargs = {'service_id': obj.service.id, 'bind_id': obj.id}
        return reverse(view_name, kwargs=kwargs, request=request, format=format)


class ServiceBindSerializer(BindSerializer):
    url = ServiceBindUrlFiels(read_only=True, view_name='service-bind-details')


class ServiceBindPostSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    export_cluster_id = serializers.IntegerField()
    export_service_id = serializers.IntegerField()
    export_cluster_name = serializers.CharField(read_only=True)
    export_service_name = serializers.CharField(read_only=True)
    export_cluster_prototype_name = serializers.CharField(read_only=True)

    def create(self, validated_data):
        export_cluster = check_obj(
            Cluster, validated_data.get('export_cluster_id'), 'CLUSTER_NOT_FOUND'
        )
        try:
            return bind(
                validated_data.get('cluster'),
                validated_data.get('service'),
                export_cluster,
                validated_data.get('export_service_id')
            )
        except AdcmEx as error:
            raise AdcmApiEx(error.code, error.msg, error.http_code) from error
