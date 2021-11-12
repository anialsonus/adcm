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
# Generated by Django 3.2.7 on 2021-10-26 13:48
import jsonschema
from rest_flex_fields.serializers import FlexFieldsSerializerMixin
from rest_framework import serializers
from rest_framework import status
from rest_framework import viewsets
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.validators import ValidationError
from rest_framework_extensions.mixins import NestedViewSetMixin

from cm.models import Cluster, ClusterObject, ServiceComponent, HostProvider, Host
from rbac.models import Policy, User, Group, Role
from .services import policy_create, policy_update


# pylint: disable=too-many-ancestors
class PolicyUserViewSet(
    NestedViewSetMixin, ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet
):
    class UserSerializer(FlexFieldsSerializerMixin, serializers.ModelSerializer):
        permissions = serializers.RelatedField(source='user_permissions', many=True, read_only=True)
        profile = serializers.PrimaryKeyRelatedField(source='userprofile', read_only=True)
        url = serializers.SerializerMethodField()

        class Meta:
            model = User
            fields = (
                'id',
                'username',
                'password',
                'first_name',
                'last_name',
                'email',
                'is_superuser',
                'groups',
                'permissions',
                'profile',
                'url',
            )
            read_only_fields = (
                'username',
                'password',
                'first_name',
                'last_name',
                'email',
                'is_superuser',
                'groups',
                'permissions',
                'profile',
                'url',
            )

        def get_url(self, obj):
            request = self.context.get('request')
            request_format = self.context.get('format')
            policy = self.context.get('policy')
            if policy is None:
                kwargs = {'id': obj.id}
                return reverse(
                    'rbac-user-detail', kwargs=kwargs, request=request, format=request_format
                )
            else:
                kwargs = {'parent_lookup_policy': self.context['policy'].id, 'pk': obj.id}
                return reverse(
                    'policy-user-detail',
                    kwargs=kwargs,
                    request=request,
                    format=request_format,
                )

    queryset = User.objects.all()
    serializer_class = UserSerializer
    fiterset_fields = '__all__'
    ordering_fields = '__all__'

    def get_serializer_context(self):
        context = super().get_serializer_context()
        policy_id = self.kwargs.get('parent_lookup_policy')
        if policy_id is not None:
            context.update({'policy': Policy.objects.get(id=policy_id)})
        return context


class PolicyGroupViewSet(
    NestedViewSetMixin, ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet
):
    class GroupSerializer(serializers.ModelSerializer):
        url = serializers.SerializerMethodField()

        class Meta:
            model = Group
            fields = (
                'id',
                'name',
                'permissions',
                'url',
            )

        def get_url(self, obj):
            request = self.context.get('request')
            request_format = self.context.get('format')
            policy = self.context.get('policy')
            if policy is None:
                kwargs = {'id': obj.id}
                return reverse(
                    'rbac_group:group-detail', kwargs=kwargs, request=request, format=request_format
                )
            else:
                kwargs = {'parent_lookup_policy': self.context['policy'].id, 'pk': obj.id}
                return reverse(
                    'policy-group-detail',
                    kwargs=kwargs,
                    request=request,
                    format=request_format,
                )

    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    filterset_fields = '__all__'
    ordering_fields = '__all__'

    def get_serializer_context(self):
        context = super().get_serializer_context()
        policy_id = self.kwargs.get('parent_lookup_policy')
        if policy_id is not None:
            context.update({'policy': Policy.objects.get(id=policy_id)})
        return context


class RoleSerializer(serializers.ModelSerializer):

    url = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = (
            'id',
            'name',
            'description',
            'permissions',
            'url',
        )

    def get_url(self, obj):
        request = self.context.get('request')
        request_format = self.context.get('format')
        kwargs = {'id': obj.id}
        return reverse(
            'rbac_role:role-detail', kwargs=kwargs, request=request, format=request_format
        )


class ObjectField(serializers.JSONField):
    def schema_validate(self, value):
        schema = {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'number'},
                    'type': {
                        'type': 'string',
                        'pattern': '^(cluster|service|component|provider|host)$',
                    },
                },
            },
        }
        try:
            jsonschema.validate(value, schema)
        except jsonschema.ValidationError:
            raise ValidationError('the field does not match the scheme') from None

    dictionary = {
        'cluster': Cluster,
        'service': ClusterObject,
        'component': ServiceComponent,
        'provider': HostProvider,
        'host': Host,
    }

    def to_internal_value(self, data):
        self.schema_validate(data)
        objects = []
        for obj in data:
            objects.append(self.dictionary[obj['type']].obj.get(id=obj['id']))
        return objects

    def to_representation(self, value):
        data = []
        for obj in value.all():
            data.append({'id': obj.object_id, 'type': obj.object.prototype.type})
        return super().to_representation(data)


class PolicyViewSet(viewsets.ModelViewSet):  # pylint: disable=too-many-ancestors
    class PolicySerializer(FlexFieldsSerializerMixin, serializers.ModelSerializer):
        url = serializers.HyperlinkedIdentityField(view_name='policy-detail')
        user_url = serializers.HyperlinkedRelatedField(
            view_name='policy-user-list',
            read_only=True,
            source='*',
            lookup_field='pk',
            lookup_url_kwarg='parent_lookup_policy',
        )
        group_url = serializers.HyperlinkedRelatedField(
            view_name='policy-group-list',
            read_only=True,
            source='*',
            lookup_field='pk',
            lookup_url_kwarg='parent_lookup_policy',
        )
        object = ObjectField()

        class Meta:
            model = Policy
            fields = (
                'id',
                'name',
                'object',
                'role',
                'user',
                'user_url',
                'group',
                'group_url',
                'url',
            )
            expandable_fields = {
                'user': (PolicyUserViewSet.UserSerializer, {'many': True}),
                'group': (PolicyGroupViewSet.GroupSerializer, {'many': True}),
                'role': RoleSerializer,
            }

    queryset = Policy.objects.all()
    serializer_class = PolicySerializer
    filterset_fields = '__all__'
    ordering_fields = '__all__'

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):

            policy = policy_create(**serializer.validated_data)

            return Response(data=self.get_serializer(policy).data, status=status.HTTP_201_CREATED)
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        policy = self.get_object()
        serializer = self.get_serializer(policy, data=request.data, partial=partial)
        if serializer.is_valid(raise_exception=True):

            policy = policy_update(policy, **serializer.validated_data)

            return Response(data=self.get_serializer(policy).data)
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
