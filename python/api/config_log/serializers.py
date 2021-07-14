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

from django.db.transaction import atomic
from rest_framework import serializers

import logrotate
from cm.adcm_config import ui_config
from cm.api import update_obj_config
from cm.models import ConfigLog


class ConfigLogSerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='config-log-detail')

    class Meta:
        model = ConfigLog
        fields = ('id', 'date', 'obj_ref', 'description', 'config', 'attr', 'url')

    @atomic
    def create(self, validated_data):
        object_config = validated_data.get('obj_ref')
        config = validated_data.get('config')
        attr = validated_data.get('attr', {})
        description = validated_data.get('description', '')
        cl = update_obj_config(object_config, config, attr, description)
        if hasattr(object_config, 'adcm'):
            logrotate.run()
        return cl


class UIConfigLogSerializer(ConfigLogSerializer):
    config = serializers.SerializerMethodField()

    class Meta:
        model = ConfigLog
        fields = ('id', 'date', 'description', 'config', 'attr', 'url')

    def get_config(self, config_log):
        obj, _ = config_log.obj_ref.get_object_and_prototype(raise_error=True)
        return ui_config(obj, config_log)
