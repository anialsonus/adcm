
import django.contrib.auth
import rest_framework.authtoken.serializers
from rest_framework import serializers

import cm.job
import cm.stack
import cm.status_api
import cm.adcm_config
from cm.errors import AdcmEx
from cm.models import Upgrade

from api.api_views import check_obj, hlink
from api.api_views import UrlField


class AuthSerializer(rest_framework.authtoken.serializers.AuthTokenSerializer):
    def validate(self, attrs):
        user = django.contrib.auth.authenticate(
            username=attrs.get('username'),
            password=attrs.get('password')
        )
        if not user:
            raise AdcmEx('AUTH_ERROR', 'Wrong user or password')
        attrs['user'] = user
        return attrs


class LogOutSerializer(serializers.Serializer):
    pass


class EmptySerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)


class UpgradeSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(required=False)
    bundle_id = serializers.IntegerField(read_only=True)
    description = serializers.CharField(required=False)
    min_version = serializers.CharField(required=False)
    max_version = serializers.CharField(required=False)
    min_strict = serializers.BooleanField(required=False)
    max_strict = serializers.BooleanField(required=False)
    upgradable = serializers.BooleanField(required=False)
    license = serializers.CharField(required=False)
    license_url = hlink('bundle-license', 'bundle_id', 'bundle_id')
    from_edition = serializers.JSONField(required=False)
    state_available = serializers.JSONField(required=False)
    state_on_success = serializers.CharField(required=False)


class UpgradeLinkSerializer(UpgradeSerializer):
    class MyUrlField(UrlField):
        def get_kwargs(self, obj):
            return {'cluster_id': self.context['cluster_id'], 'upgrade_id': obj.id}

    url = MyUrlField(read_only=True, view_name='cluster-upgrade-details')
    do = MyUrlField(read_only=True, view_name='do-cluster-upgrade')


class DoUpgradeSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    upgradable = serializers.BooleanField(read_only=True)

    def create(self, validated_data):
        upgrade = check_obj(Upgrade, validated_data.get('upgrade_id'), 'UPGRADE_NOT_FOUND')
        return cm.upgrade.do_upgrade(validated_data.get('obj'), upgrade)
