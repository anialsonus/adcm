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

# pylint: disable=duplicate-except,attribute-defined-outside-init,arguments-differ

import rest_framework
from django.contrib.auth import login as django_login
from django.contrib.auth.models import User, Group
from django.db import transaction
from django.utils import timezone
from django_filters import rest_framework as drf_filters
from rest_framework import routers, status
from rest_framework.authtoken.models import Token
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

import api.serializers
import cm.api
import cm.config as config
import cm.job
import cm.stack
import cm.status_api
import cm.upgrade
from adcm.settings import ADCM_VERSION
from api.api_views import (
    DetailViewRO, DetailViewDelete, ActionFilter, ListView,
    PageView, PageViewAdd, GenericAPIPermView, create, update
)
from api.serializers import check_obj, filter_actions
from cm.api import safe_api
from cm.errors import AdcmEx, AdcmApiEx
from cm.models import (
    HostProvider, Host, ADCM, Action, JobLog, TaskLog, Upgrade,
    UserProfile, DummyData, Role,
)


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


class APIRoot(routers.APIRootView):
    """
    Arenadata Chapel API
    """
    permission_classes = (rest_framework.permissions.AllowAny,)
    api_root_dict = {
        'adcm': 'adcm',
        'cluster': 'cluster',
        'profile': 'profile-list',
        'provider': 'provider',
        'host': 'host',
        'job': 'job',
        'stack': 'stack',
        'stats': 'stats',
        'task': 'task',
        'token': 'token',
        'user': 'user-list',
        'group': 'group-list',
        'role': 'role-list',
        'info': 'adcm-info',
    }


class NameConverter:
    regex = cm.stack.NAME_REGEX

    def to_python(self, value):
        return value

    def to_url(self, value):
        return value


class GetAuthToken(GenericAPIView):
    authentication_classes = (rest_framework.authentication.TokenAuthentication,)
    permission_classes = (rest_framework.permissions.AllowAny,)
    serializer_class = api.serializers.AuthSerializer

    def post(self, request, *args, **kwargs):
        """
        Provide authentication token

        HTTP header for authorization:

        ```
        Authorization: Token XXXXX
        ```
        """
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, _created = Token.objects.get_or_create(user=user)
        django_login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        return Response({'token': token.key})


class ADCMInfo(GenericAPIView):
    permission_classes = (rest_framework.permissions.AllowAny,)
    serializer_class = api.serializers.EmptySerializer

    def get(self, request):
        """
        General info about ADCM
        """
        return Response({
            'adcm_version': ADCM_VERSION,
            'google_oauth': cm.api.has_google_oauth()
        })


class UserList(PageViewAdd):
    """
    get:
    List all existing users

    post:
    Create new user
    """
    queryset = User.objects.all()
    serializer_class = api.serializers.UserSerializer
    ordering_fields = ('username',)


class UserDetail(GenericAPIPermView):
    queryset = User.objects.all()
    serializer_class = api.serializers.UserDetailSerializer

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
    serializer_class = api.serializers.UserPasswdSerializer

    def patch(self, request, username):
        """
        Change user password
        """
        user = check_obj(User, {'username': username}, 'USER_NOT_FOUND')
        serializer = self.serializer_class(user, data=request.data, context={'request': request})
        return update(serializer)


class AddUser2Group(GenericAPIPermView):
    queryset = User.objects.all()
    serializer_class = api.serializers.AddUser2GroupSerializer

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
        group = check_obj(
            Group, {'name': serializer.data['name']}, 'GROUP_NOT_FOUND'
        )
        group.user_set.remove(user)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ChangeUserRole(GenericAPIPermView):
    queryset = User.objects.all()
    serializer_class = api.serializers.AddUserRoleSerializer

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
        safe_api(cm.api.remove_user_role, (user, role))
        return Response(status=status.HTTP_204_NO_CONTENT)


class GroupList(PageViewAdd):
    """
    get:
    List all existing user groups

    post:
    Create new user group
    """
    queryset = Group.objects.all()
    serializer_class = api.serializers.GroupSerializer
    ordering_fields = ('name',)


class GroupDetail(GenericAPIPermView):
    queryset = Group.objects.all()
    serializer_class = api.serializers.GroupDetailSerializer

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
    serializer_class = api.serializers.AddGroupRoleSerializer

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
        safe_api(cm.api.remove_group_role, (group, role))
        return Response(status=status.HTTP_204_NO_CONTENT)


class RoleList(PageView):
    """
    get:
    List all existing roles
    """
    queryset = Role.objects.all()
    serializer_class = api.serializers.RoleSerializer
    ordering_fields = ('name',)


class RoleDetail(PageView):
    queryset = Role.objects.all()
    serializer_class = api.serializers.RoleDetailSerializer

    def get(self, request, role_id):
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
    serializer_class = api.serializers.ProfileSerializer
    ordering_fields = ('username',)


class ProfileDetail(DetailViewRO):
    """
    get:
    Show user profile
    """
    queryset = UserProfile.objects.all()
    serializer_class = api.serializers.ProfileDetailSerializer
    lookup_field = 'login'
    lookup_url_kwarg = 'username'
    error_code = 'USER_NOT_FOUND'

    def get_object(self):
        login = self.kwargs['username']
        try:
            up = UserProfile.objects.get(login=login)
        except UserProfile.DoesNotExist:
            try:
                user = User.objects.get(username=login)
                up = UserProfile.objects.create(login=user.username)
                up.save()
            except User.DoesNotExist:
                raise AdcmApiEx('USER_NOT_FOUND')
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


class AdcmList(ListView):
    """
    get:
    List adcm object
    """
    queryset = ADCM.objects.all()
    serializer_class = api.serializers.AdcmSerializer
    serializer_class_ui = api.serializers.AdcmDetailSerializer


class AdcmDetail(DetailViewRO):
    """
    get:
    Show adcm object
    """
    queryset = ADCM.objects.all()
    serializer_class = api.serializers.AdcmDetailSerializer
    lookup_field = 'id'
    lookup_url_kwarg = 'adcm_id'
    error_code = 'ADCM_NOT_FOUND'


class ADCMActionList(ListView):
    queryset = Action.objects.filter(prototype__type='adcm')
    serializer_class = api.serializers.ADCMActionList
    serializer_class_ui = api.serializers.ProviderActionDetail
    filterset_class = ActionFilter
    filterset_fields = ('name', 'button', 'button_is_null')

    def get(self, request, adcm_id):
        """
        List all actions of an ADCM
        """
        adcm = check_obj(ADCM, adcm_id, 'ADCM_NOT_FOUND')
        obj = filter_actions(adcm, self.filter_queryset(
            self.get_queryset().filter(prototype=adcm.prototype)
        ))
        serializer_class = self.select_serializer(request)
        serializer = serializer_class(
            obj, many=True, context={'request': request, 'adcm_id': adcm_id}
        )
        return Response(serializer.data)


class ADCMAction(GenericAPIPermView):
    queryset = Action.objects.filter(prototype__type='adcm')
    serializer_class = api.serializers.ADCMActionDetail

    def get(self, request, adcm_id, action_id):
        """
        Show specified action of an ADCM
        """
        adcm = check_obj(ADCM, adcm_id, 'ADCM_NOT_FOUND')
        obj = filter_actions(adcm, self.get_queryset().filter(prototype=adcm.prototype))
        obj = check_obj(
            Action,
            {'prototype': adcm.prototype, 'id': action_id},
            'ACTION_NOT_FOUND'
        )
        serializer = self.serializer_class(
            obj, context={'request': request, 'adcm_id': adcm_id}
        )
        return Response(serializer.data)


class ADCMTask(GenericAPIPermView):
    queryset = TaskLog.objects.all()
    serializer_class = api.serializers.TaskRunSerializer

    def post(self, request, adcm_id, action_id):
        """
        Ran specified action of a specified host provider
        """
        adcm = check_obj(ADCM, adcm_id, 'ADCM_NOT_FOUND')
        check_obj(
            Action,
            {'prototype': adcm.prototype, 'id': action_id},
            'ACTION_NOT_FOUND'
        )
        serializer = self.serializer_class(data=request.data, context={'request': request})
        return create(serializer, action_id=int(action_id), selector={'adcm': adcm.id})


class ProviderList(PageViewAdd):
    """
    get:
    List all host providers

    post:
    Create new host provider
    """
    queryset = HostProvider.objects.all()
    serializer_class = api.serializers.ProviderSerializer
    serializer_class_ui = api.serializers.ProviderUISerializer
    serializer_class_post = api.serializers.ProviderDetailSerializer
    filterset_fields = ('name', 'prototype_id')
    ordering_fields = ('name', 'state', 'prototype__display_name', 'prototype__version_order')


class ProviderDetail(DetailViewDelete):
    """
    get:
    Show host provider
    """
    queryset = HostProvider.objects.all()
    serializer_class = api.serializers.ProviderDetailSerializer
    serializer_class_ui = api.serializers.ProviderUISerializer
    lookup_field = 'id'
    lookup_url_kwarg = 'provider_id'
    error_code = 'PROVIDER_NOT_FOUND'

    def delete(self, request, provider_id):
        """
        Remove host provider
        """
        provider = check_obj(HostProvider, provider_id, 'PROVIDER_NOT_FOUND')
        try:
            cm.api.delete_host_provider(provider)
        except AdcmEx as e:
            raise AdcmApiEx(e.code, e.msg, e.http_code)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ProviderHostList(PageView):
    """
    post:
    Create new host
    """
    queryset = Host.objects.all()
    serializer_class = api.serializers.ProviderHostSerializer
    serializer_class_ui = api.serializers.HostUISerializer
    filterset_fields = ('fqdn', 'cluster_id')
    ordering_fields = (
        'fqdn', 'state', 'prototype__display_name', 'prototype__version_order'
    )

    def get(self, request, provider_id):
        """
        List all hosts of specified host provider
        """
        provider = check_obj(HostProvider, provider_id, 'PROVIDER_NOT_FOUND')
        obj = self.filter_queryset(self.get_queryset().filter(provider=provider))
        return self.get_page(obj, request)

    def post(self, request, provider_id):
        provider = check_obj(HostProvider, provider_id, 'PROVIDER_NOT_FOUND')
        serializer_class = self.select_serializer(request)
        serializer = serializer_class(
            data=request.data, context={'request': request, 'provider': provider}
        )
        return create(serializer, provider=provider)


class HostFilter(drf_filters.FilterSet):
    cluster_is_null = drf_filters.BooleanFilter(field_name='cluster_id', lookup_expr='isnull')
    provider_is_null = drf_filters.BooleanFilter(field_name='provider_id', lookup_expr='isnull')

    class Meta:
        model = Host
        fields = ['cluster_id', 'prototype_id', 'provider_id', 'fqdn']


class HostList(PageViewAdd):
    """
    get:
    List all hosts

    post:
    Create new host
    """
    queryset = Host.objects.all()
    serializer_class = api.serializers.HostSerializer
    serializer_class_ui = api.serializers.HostUISerializer
    serializer_class_post = api.serializers.HostDetailSerializer
    filterset_class = HostFilter
    filterset_fields = (
        'cluster_id', 'prototype_id', 'provider_id', 'fqdn', 'cluster_is_null', 'provider_is_null'
    )   # just for documentation
    ordering_fields = (
        'fqdn', 'state', 'provider__name', 'cluster__name',
        'prototype__display_name', 'prototype__version_order',
    )


class HostDetail(DetailViewDelete):
    """
    get:
    Show host
    """
    queryset = Host.objects.all()
    serializer_class = api.serializers.HostDetailSerializer
    serializer_class_ui = api.serializers.HostUISerializer
    lookup_field = 'id'
    lookup_url_kwarg = 'host_id'
    error_code = 'HOST_NOT_FOUND'

    def delete(self, request, host_id):
        """
        Remove host (and all corresponding host services:components)
        """
        host = check_obj(Host, host_id, 'HOST_NOT_FOUND')
        try:
            cm.api.delete_host(host)
        except AdcmEx as e:
            raise AdcmApiEx(e.code, e.msg, e.http_code)
        return Response(status=status.HTTP_204_NO_CONTENT)


class Stats(GenericAPIPermView):
    queryset = JobLog.objects.all()
    serializer_class = api.serializers.StatsSerializer

    def get(self, request):
        """
        Statistics
        """
        obj = JobLog(id=1)
        serializer = self.serializer_class(obj, context={'request': request})
        return Response(serializer.data)


class JobStats(GenericAPIPermView):
    queryset = JobLog.objects.all()
    serializer_class = api.serializers.EmptySerializer

    def get(self, request, job_id):
        """
        Show jobs stats
        """
        jobs = self.get_queryset().filter(id__gt=job_id)
        data = {
            config.Job.FAILED: jobs.filter(status=config.Job.FAILED).count(),
            config.Job.SUCCESS: jobs.filter(status=config.Job.SUCCESS).count(),
            config.Job.RUNNING: jobs.filter(status=config.Job.RUNNING).count(),
        }
        return Response(data)


class TaskStats(GenericAPIPermView):
    queryset = TaskLog.objects.all()
    serializer_class = api.serializers.EmptySerializer

    def get(self, request, task_id):
        """
        Show tasks stats
        """
        tasks = self.get_queryset().filter(id__gt=task_id)
        data = {
            config.Job.FAILED: tasks.filter(status=config.Job.FAILED).count(),
            config.Job.SUCCESS: tasks.filter(status=config.Job.SUCCESS).count(),
            config.Job.RUNNING: tasks.filter(status=config.Job.RUNNING).count(),
        }
        return Response(data)


class ProviderActionList(ListView):
    queryset = Action.objects.filter(prototype__type='provider')
    serializer_class = api.serializers.ProviderActionList
    serializer_class_ui = api.serializers.ProviderActionDetail
    filterset_class = ActionFilter
    filterset_fields = ('name', 'button', 'button_is_null')

    def get(self, request, provider_id):
        """
        List all actions of a specified host provider
        """
        provider = check_obj(HostProvider, provider_id, 'PROVIDER_NOT_FOUND')
        obj = filter_actions(provider, self.filter_queryset(
            self.get_queryset().filter(prototype=provider.prototype)
        ))
        serializer_class = self.select_serializer(request)
        serializer = serializer_class(
            obj, many=True, context={'request': request, 'provider_id': provider_id}
        )
        return Response(serializer.data)


class ProviderAction(GenericAPIPermView):
    queryset = Action.objects.filter(prototype__type='provider')
    serializer_class = api.serializers.ProviderActionDetail

    def get(self, request, provider_id, action_id):
        """
        Show specified action of a specified host provider
        """
        provider = check_obj(HostProvider, provider_id, 'PROVIDER_NOT_FOUND')
        obj = filter_actions(provider, self.get_queryset().filter(prototype=provider.prototype))
        obj = check_obj(
            Action,
            {'prototype': provider.prototype, 'id': action_id},
            'ACTION_NOT_FOUND'
        )
        serializer = self.serializer_class(
            obj, context={'request': request, 'provider_id': provider_id}
        )
        return Response(serializer.data)


class ProviderTask(GenericAPIPermView):
    queryset = TaskLog.objects.all()
    serializer_class = api.serializers.TaskRunSerializer

    def post(self, request, provider_id, action_id):
        """
        Ran specified action of a specified host provider
        """
        provider = check_obj(HostProvider, provider_id, 'PROVIDER_NOT_FOUND')
        check_obj(
            Action,
            {'prototype': provider.prototype, 'id': action_id},
            'ACTION_NOT_FOUND'
        )
        serializer = self.serializer_class(data=request.data, context={'request': request})
        return create(serializer, action_id=int(action_id), selector={'provider': provider.id})


class ProviderUpgrade(PageView):
    queryset = Upgrade.objects.all()
    serializer_class = api.serializers.UpgradeProviderSerializer

    def get(self, request, provider_id):
        """
        List all avaliable upgrades for specified host provider
        """
        provider = check_obj(HostProvider, provider_id, 'PROVIDER_NOT_FOUND')
        obj = cm.upgrade.get_upgrade(provider, self.get_ordering(request, self.queryset, self))
        serializer = self.serializer_class(obj, many=True, context={
            'provider_id': provider.id, 'request': request
        })
        return Response(serializer.data)


class ProviderUpgradeDetail(ListView):
    queryset = Upgrade.objects.all()
    serializer_class = api.serializers.UpgradeProviderSerializer

    def get(self, request, provider_id, upgrade_id):
        """
        List all avaliable upgrades for specified host provider
        """
        provider = check_obj(HostProvider, provider_id, 'PROVIDER_NOT_FOUND')
        obj = self.get_queryset().get(id=upgrade_id)
        serializer = self.serializer_class(obj, context={
            'provider_id': provider.id, 'request': request
        })
        return Response(serializer.data)


class DoProviderUpgrade(GenericAPIPermView):
    queryset = Upgrade.objects.all()
    serializer_class = api.serializers.DoUpgradeSerializer

    def post(self, request, provider_id, upgrade_id):
        """
        Do upgrade specified host provider
        """
        provider = check_obj(HostProvider, provider_id, 'PROVIDER_NOT_FOUND')
        serializer = self.serializer_class(data=request.data, context={'request': request})
        return create(serializer, upgrade_id=int(upgrade_id), obj=provider)


class HostActionList(ListView):
    queryset = Action.objects.filter(prototype__type='host')
    serializer_class = api.serializers.HostActionList
    serializer_class_ui = api.serializers.HostActionDetail
    filterset_class = ActionFilter
    filterset_fields = ('name', 'button', 'button_is_null')

    def get(self, request, host_id):
        """
        List all actions of a specified host
        """
        host = check_obj(Host, host_id, 'HOST_NOT_FOUND')
        obj = filter_actions(host, self.filter_queryset(
            self.get_queryset().filter(prototype=host.prototype)
        ))
        serializer_class = self.select_serializer(request)
        serializer = serializer_class(
            obj, many=True, context={'request': request, 'host_id': host_id}
        )
        return Response(serializer.data)


class HostAction(GenericAPIPermView):
    queryset = Action.objects.filter(prototype__type='host')
    serializer_class = api.serializers.HostActionDetail

    def get(self, request, host_id, action_id):
        """
        Show specified action of a specified host
        """
        host = check_obj(Host, host_id, 'HOST_NOT_FOUND')
        obj = check_obj(
            Action,
            {'prototype': host.prototype, 'id': action_id},
            'ACTION_NOT_FOUND'
        )
        serializer = self.serializer_class(
            obj, context={'request': request, 'host_id': host_id}
        )
        return Response(serializer.data)


class HostTask(GenericAPIPermView):
    queryset = TaskLog.objects.all()
    serializer_class = api.serializers.TaskRunSerializer

    def post(self, request, host_id, action_id):
        """
        Ran specified action of a specified host
        """
        host = check_obj(Host, host_id, 'HOST_NOT_FOUND')
        check_obj(
            Action,
            {'prototype': host.prototype, 'id': action_id},
            'ACTION_NOT_FOUND'
        )
        serializer = self.serializer_class(data=request.data, context={'request': request})
        return create(serializer, action_id=int(action_id), selector={'host': host.id})
