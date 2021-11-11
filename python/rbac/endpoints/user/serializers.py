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

"""User serializers"""

from django.db import models
from django.db.transaction import atomic
from django.contrib.auth.models import User, Group, Permission

from rest_flex_fields.serializers import FlexFieldsSerializerMixin
from rest_framework import serializers
from rest_framework.reverse import reverse
from rest_framework.authtoken.models import Token
from rest_framework.utils import model_meta

from adwp_base.errors import raise_AdwpEx as err
from rbac.models import Role, UserProfile


class PasswordField(serializers.CharField):
    """Password serializer field"""

    def to_representation(self, value):
        return '******'


def get_group_url(self, obj):
    """get group URL rbac/user/1/group/1/"""
    kwargs = {'id': self.context['user'].id, 'group_id': obj.id}
    return reverse('rbac_user_group:detail', kwargs=kwargs, request=self.context['request'])


def get_role_url(self, obj):
    """get role URL rbac/user/1/role/1/"""
    kwargs = {'id': self.context['user'].id, 'role_id': obj.id}
    return reverse('rbac_user_role:detail', kwargs=kwargs, request=self.context['request'])


class GroupSerializer(serializers.ModelSerializer):
    """Group serializer"""

    url = serializers.SerializerMethodField()
    get_url = get_group_url

    class Meta:
        model = Group
        fields = (
            'id',
            'name',
            'url',
        )


class RoleSerializer(FlexFieldsSerializerMixin, serializers.HyperlinkedModelSerializer):
    """Role serializer"""

    class Meta:
        model = Role
        fields = (
            'id',
            'name',
            'url',
        )
        extra_kwargs = {
            'url': {'view_name': 'rbac_role:role-detail', 'lookup_field': 'id'},
        }


class PermissionSerializer(serializers.ModelSerializer):
    """Permission serializer"""

    app_label = serializers.SerializerMethodField()
    model = serializers.SerializerMethodField()

    class Meta:
        model = Permission
        fields = (
            'name',
            'codename',
            'app_label',
            'model',
        )

    def get_app_label(self, obj):
        return obj.content_type.app_label

    def get_model(self, obj):
        return obj.content_type.model


class ProfileField(serializers.JSONField):
    """Get profile field from one to one model UserProfile"""

    def get_attribute(self, instance):
        return instance.userprofile.profile


class UserGroupSerializer(serializers.ModelSerializer):
    """Serializer for user's groups"""

    id = serializers.PrimaryKeyRelatedField(queryset=Group.objects.all())
    url = serializers.SerializerMethodField()
    get_url = get_group_url

    class Meta:
        model = Group
        fields = (
            'id',
            'name',
            'url',
        )
        read_only_fields = ('name',)

    def create(self, validated_data):
        """Add user to group"""
        user = self.context.get('user')
        group = validated_data['id']
        user.groups.add(group)
        return group


class UserRoleSerializer(serializers.ModelSerializer):
    """Serializer for user's roles"""

    id = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())
    url = serializers.SerializerMethodField()
    get_url = get_role_url

    class Meta:
        model = Group
        fields = (
            'id',
            'name',
            'url',
        )
        read_only_fields = ('name',)

    def create(self, validated_data):
        """Add role to user"""
        user = self.context.get('user')
        role = validated_data['id']
        role.add_user(user)
        return role


class UserSerializer(FlexFieldsSerializerMixin, serializers.HyperlinkedModelSerializer):
    """User serializer"""

    password = PasswordField()
    profile = ProfileField(required=False)
    groups = serializers.SerializerMethodField(read_only=True)
    permissions = PermissionSerializer(many=True, source='user_permissions', read_only=True)
    add_group = serializers.HyperlinkedIdentityField(
        view_name='rbac_user_group:list', lookup_field='id'
    )
    add_role = serializers.HyperlinkedIdentityField(
        view_name='rbac_user_role:list', lookup_field='id'
    )
    change_password = serializers.HyperlinkedIdentityField(
        view_name='rbac-user-change-password', lookup_field='id'
    )

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
            'add_group',
            'add_role',
            'change_password',
        )
        extra_kwargs = {
            'url': {'view_name': 'rbac-user-detail', 'lookup_field': 'id'},
            'is_superuser': {'required': False},
        }

    def get_groups(self, obj):
        """Get all user's groups"""
        self.context['user'] = obj
        return GroupSerializer(obj.groups.all(), many=True, context=self.context).data

    @atomic
    def create(self, validated_data):
        """Create User and UserProile"""
        extra_fields = {}

        def set_extra(name):
            if name in validated_data:
                extra_fields[name] = validated_data[name]

        for name in ('first_name', 'last_name'):
            set_extra(name)

        user = User.objects.create_user(
            validated_data.get('username'),
            password=validated_data.get('password'),
            is_superuser=validated_data.get('is_superuser', True),
            email=validated_data.get('email', None),
            **extra_fields,
        )
        UserProfile.objects.create(user=user, profile=validated_data.get('profile', ""))
        return user

    @atomic
    def update(self, instance, validated_data):
        """Update user, use in PUT and PATCH methods"""
        if 'username' in validated_data:
            err('USER_UPDATE_ERROR', "Can't change user name")
        if 'password' in validated_data:
            password = validated_data.pop('password')
            instance.set_password(password)
            instance.save()
            token, _ = Token.objects.get_or_create(user=instance)
            token.delete()
            token.key = token.generate_key()
            token.user = instance
            token.save()
        if 'profile' in validated_data:
            user_profile = instance.userprofile
            user_profile.profile = validated_data['profile']
            user_profile.save()

        return super().update(instance, validated_data)

    def get_fields(self):
        """Get fields for serialization, remove `huge` fields"""
        fields = super().get_fields()
        action = getattr(self.context.get('view'), 'action', '')
        if action == 'list':
            model_field_info = model_meta.get_field_info(User)
            for name, field in model_field_info.fields.items():
                if name in fields:
                    if isinstance(field, (models.JSONField, models.TextField)):
                        del fields[name]
        return fields
