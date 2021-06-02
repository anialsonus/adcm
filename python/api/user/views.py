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

from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User, Group
from rest_framework import status
from rest_framework.response import Response

from api.api_views import PageView, PageViewAdd, DetailViewRO, GenericAPIPermView, update

import cm.api
from cm.errors import AdcmEx
from cm.models import Role, UserProfile, DummyData
from . import serializers


def check_obj(model, req, error=None):
    if isinstance(req, dict):
        kw = req
    else:
        kw = {'id': req}
    try:
        return model.objects.get(**kw)
    except ObjectDoesNotExist:
        raise AdcmEx(error) from None


@transaction.atomic
def delete_user(username):
    DummyData.objects.filter(id=1).update(date=timezone.now())
    user = check_obj(User, {'username': username}, 'USER_NOT_FOUND')
    try:
        profile = UserProfile.objects.get(login=user.username)
        profile.delete()
    except UserProfile.DoesNotExist:
        pass
    user.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


class UserList(PageViewAdd):
    """
    get:
    List all existing users

    post:
    Create new user
    """

    queryset = User.objects.all()
    serializer_class = serializers.UserSerializer
    ordering_fields = ('username',)


class UserDetail(GenericAPIPermView):
    queryset = User.objects.all()
    serializer_class = serializers.UserDetailSerializer

    def get(self, request, username):
        """
        show user
        """
        user = check_obj(User, {'username': username}, 'USER_NOT_FOUND')
        serializer = self.serializer_class(user, context={'request': request})
        return Response(serializer.data)

    def delete(self, request, username):
        """
        delete user and profile
        """
        return delete_user(username)


class UserPasswd(GenericAPIPermView):
    queryset = User.objects.all()
    serializer_class = serializers.UserPasswdSerializer

    def patch(self, request, username):
        """
        Change user password
        """
        user = check_obj(User, {'username': username}, 'USER_NOT_FOUND')
        serializer = self.serializer_class(user, data=request.data, context={'request': request})
        return update(serializer)


class AddUser2Group(GenericAPIPermView):
    queryset = User.objects.all()
    serializer_class = serializers.AddUser2GroupSerializer

    def post(self, request, username):
        """
        Add user to group
        """
        user = check_obj(User, {'username': username}, 'USER_NOT_FOUND')
        serializer = self.serializer_class(user, data=request.data, context={'request': request})
        return update(serializer)

    def delete(self, request, username):
        """
        Remove user from group
        """
        user = check_obj(User, {'username': username}, 'USER_NOT_FOUND')
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        group = check_obj(Group, {'name': serializer.data['name']}, 'GROUP_NOT_FOUND')
        group.user_set.remove(user)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ChangeUserRole(GenericAPIPermView):
    queryset = User.objects.all()
    serializer_class = serializers.AddUserRoleSerializer

    def post(self, request, username):
        """
        Add user role
        """
        user = check_obj(User, {'username': username}, 'USER_NOT_FOUND')
        serializer = self.serializer_class(user, data=request.data, context={'request': request})
        return update(serializer)

    def delete(self, request, username):
        """
        Remove user role
        """
        user = check_obj(User, {'username': username}, 'USER_NOT_FOUND')
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        role = check_obj(Role, {'id': serializer.data['role_id']}, 'ROLE_NOT_FOUND')
        cm.api.remove_user_role(user, role)
        return Response(status=status.HTTP_204_NO_CONTENT)


class GroupList(PageViewAdd):
    """
    get:
    List all existing user groups

    post:
    Create new user group
    """

    queryset = Group.objects.all()
    serializer_class = serializers.GroupSerializer
    ordering_fields = ('name',)


class GroupDetail(GenericAPIPermView):
    queryset = Group.objects.all()
    serializer_class = serializers.GroupDetailSerializer

    def get(self, request, name):
        """
        show user group
        """
        group = check_obj(Group, {'name': name}, 'GROUP_NOT_FOUND')
        serializer = self.serializer_class(group, context={'request': request})
        return Response(serializer.data)

    def delete(self, request, name):
        """
        delete user group
        """
        group = check_obj(Group, {'name': name}, 'GROUP_NOT_FOUND')
        group.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ChangeGroupRole(GenericAPIPermView):
    queryset = User.objects.all()
    serializer_class = serializers.AddGroupRoleSerializer

    def post(self, request, name):
        """
        Add group role
        """
        group = check_obj(Group, {'name': name}, 'GROUP_NOT_FOUND')
        serializer = self.serializer_class(group, data=request.data, context={'request': request})
        return update(serializer)

    def delete(self, request, name):
        """
        Remove group role
        """
        group = check_obj(Group, {'name': name}, 'GROUP_NOT_FOUND')
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        role = check_obj(Role, {'id': serializer.data['role_id']}, 'ROLE_NOT_FOUND')
        cm.api.remove_group_role(group, role)
        return Response(status=status.HTTP_204_NO_CONTENT)


class RoleList(PageView):
    """
    get:
    List all existing roles
    """

    queryset = Role.objects.all()
    serializer_class = serializers.RoleSerializer
    ordering_fields = ('name',)


class RoleDetail(PageView):
    queryset = Role.objects.all()
    serializer_class = serializers.RoleDetailSerializer

    def get(self, request, role_id):  # pylint: disable=arguments-differ
        """
        show role
        """
        role = check_obj(Role, {'id': role_id}, 'ROLE_NOT_FOUND')
        serializer = self.serializer_class(role, context={'request': request})
        return Response(serializer.data)


class ProfileList(PageViewAdd):
    """
    get:
    List all existing user's profiles

    post:
    Create new user profile
    """

    queryset = UserProfile.objects.all()
    serializer_class = serializers.ProfileSerializer
    ordering_fields = ('username',)


class ProfileDetail(DetailViewRO):
    """
    get:
    Show user profile
    """

    queryset = UserProfile.objects.all()
    serializer_class = serializers.ProfileDetailSerializer
    lookup_field = 'login'
    lookup_url_kwarg = 'username'
    error_code = 'USER_NOT_FOUND'

    def get_object(self):
        login = self.kwargs['username']
        try:
            up = UserProfile.objects.get(login=login)
        except UserProfile.DoesNotExist:
            user = User.obj.get(username=login)
            up = UserProfile.objects.create(login=user.username)
            up.save()
        return up

    def patch(self, request, *args, **kwargs):
        """
        Edit user profile
        """
        obj = self.get_object()
        serializer = self.serializer_class(obj, data=request.data, context={'request': request})
        return update(serializer)

    def delete(self, request, username):
        """
        delete user and profile
        """
        return delete_user(username)
