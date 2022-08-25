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

"""User view sets"""

from adwp_base.errors import AdwpEx
from guardian.mixins import PermissionListMixin
from rest_flex_fields.serializers import FlexFieldsSerializerMixin
from rest_framework.serializers import (
    BooleanField,
    CharField,
    EmailField,
    HyperlinkedIdentityField,
    IntegerField,
    JSONField,
    ModelSerializer,
    RegexField,
    Serializer,
)
from rest_framework.status import HTTP_405_METHOD_NOT_ALLOWED
from rest_framework.viewsets import ModelViewSet

from adcm.permissions import DjangoModelPermissionsAudit
from adcm.serializers import EmptySerializer
from audit.utils import audit
from rbac import models
from rbac.services import user as user_services


class PasswordField(CharField):
    """Text field with content masking for passwords"""

    def to_representation(self, value):
        return user_services.PW_MASK


class GroupSerializer(EmptySerializer):
    """Simple Group representation serializer"""

    id = IntegerField()
    url = HyperlinkedIdentityField(view_name='rbac:group-detail')


class GroupUserSerializer(EmptySerializer):
    id = IntegerField()
    url = HyperlinkedIdentityField(view_name='rbac:user-detail')


class ExpandedGroupSerializer(FlexFieldsSerializerMixin, ModelSerializer):
    """Expanded Group serializer"""

    user = GroupUserSerializer(many=True, source='user_set')
    url = HyperlinkedIdentityField(view_name='rbac:group-detail')
    name = CharField(max_length=150, source='group.display_name')

    class Meta:
        model = models.Group
        fields = ('id', 'name', 'user', 'url')
        expandable_fields = {
            'user': (
                'rbac.endpoints.user.views.UserSerializer',
                {'many': True, 'source': 'user_set'},
            )
        }


class UserSerializer(FlexFieldsSerializerMixin, Serializer):
    """
    User serializer
    User model inherits 'groups' property from parent class, which refers to 'auth.Group',
    so it has not our custom properties in expanded fields
    """

    id = IntegerField(read_only=True)
    username = RegexField(r'^[^\s]+$', max_length=150)
    first_name = RegexField(
        r'^[^\n]*$', max_length=150, allow_blank=True, required=False, default=''
    )
    last_name = RegexField(
        r'^[^\n]*$', max_length=150, allow_blank=True, required=False, default=''
    )
    email = EmailField(
        allow_blank=True,
        required=False,
        default='',
    )
    is_superuser = BooleanField(default=False)
    password = PasswordField(trim_whitespace=False)
    url = HyperlinkedIdentityField(view_name='rbac:user-detail')
    profile = JSONField(required=False, default='')
    group = GroupSerializer(many=True, required=False, source='groups')
    built_in = BooleanField(read_only=True)
    type = CharField(read_only=True)
    is_active = BooleanField(read_only=True)

    class Meta:
        expandable_fields = {'group': (ExpandedGroupSerializer, {'many': True, 'source': 'groups'})}

    def update(self, instance, validated_data):
        context_user = self.context['request'].user
        return user_services.update(instance, context_user, partial=self.partial, **validated_data)

    def create(self, validated_data):
        return user_services.create(**validated_data)


class UserViewSet(PermissionListMixin, ModelViewSet):  # pylint: disable=too-many-ancestors
    """User view set"""

    queryset = models.User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (DjangoModelPermissionsAudit,)
    permission_required = ['rbac.view_user']
    filterset_fields = (
        'id',
        'username',
        'first_name',
        'last_name',
        'email',
        'is_superuser',
        'built_in',
    )
    ordering_fields = ('id', 'username', 'first_name', 'last_name', 'email', 'is_superuser')
    search_fields = ('username', 'first_name', 'last_name', 'email')

    @audit
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @audit
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @audit
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.built_in:
            raise AdwpEx(
                'USER_DELETE_ERROR',
                msg='Built-in user could not be deleted',
                http_code=HTTP_405_METHOD_NOT_ALLOWED,
            )
        return super().destroy(request, args, kwargs)
