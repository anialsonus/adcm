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

from rest_framework import serializers
from rest_framework.reverse import reverse

from api.action.serializers import ActionShort
from api.api_views import hlink, filter_actions, get_api_url_kwargs, CommonAPIURL

from api.concern.serializers import ConcernItemSerializer, ConcernItemUISerializer
from api.group_config.serializers import GroupConfigsHyperlinkedIdentityField
from api.serializers import StringListSerializer
from cm import status_api
from cm.models import Action


class ComponentObjectUrlField(serializers.HyperlinkedIdentityField):
    def get_url(self, obj, view_name, request, format):
        kwargs = get_api_url_kwargs(obj, request, True)
        return reverse(view_name, kwargs=kwargs, request=request, format=format)


class ComponentSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    cluster_id = serializers.IntegerField(read_only=True)
    service_id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(read_only=True)
    display_name = serializers.SerializerMethodField()
    description = serializers.CharField(read_only=True)
    state = serializers.CharField(read_only=True)
    prototype_id = serializers.IntegerField(required=True, help_text='id of component prototype')
    url = ComponentObjectUrlField(read_only=True, view_name='component-details')

    def get_display_name(self, obj):
        return obj.prototype.display_name


class ComponentDetailSerializer(ComponentSerializer):
    constraint = serializers.JSONField(read_only=True)
    requires = serializers.JSONField(read_only=True)
    bound_to = serializers.JSONField(read_only=True)
    bundle_id = serializers.IntegerField(read_only=True)
    monitoring = serializers.CharField(read_only=True)
    status = serializers.SerializerMethodField()
    action = CommonAPIURL(read_only=True, view_name='object-action')
    config = CommonAPIURL(read_only=True, view_name='object-config')
    prototype = hlink('component-type-details', 'prototype_id', 'prototype_id')
    multi_state = StringListSerializer(read_only=True)
    concerns = ConcernItemSerializer(many=True, read_only=True)
    locked = serializers.BooleanField(read_only=True)
    group_config = GroupConfigsHyperlinkedIdentityField(view_name='group-config-list')

    def get_status(self, obj):
        return status_api.get_component_status(obj.id)


class ComponentUISerializer(ComponentDetailSerializer):
    actions = serializers.SerializerMethodField()
    version = serializers.SerializerMethodField()
    concerns = ConcernItemUISerializer(many=True, read_only=True)

    def get_actions(self, obj):
        act_set = Action.objects.filter(prototype=obj.prototype)
        self.context['object'] = obj
        self.context['component_id'] = obj.id
        actions = filter_actions(obj, act_set)
        acts = ActionShort(actions, many=True, context=self.context)
        return acts.data

    def get_version(self, obj):
        return obj.prototype.version
