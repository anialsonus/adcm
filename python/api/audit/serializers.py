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


from audit.models import AuditLog, AuditSession
from rest_framework import serializers


class AuditLogSerializer(serializers.ModelSerializer):
    object_id = serializers.IntegerField(read_only=True, source='audit_object.object_id')
    object_type = serializers.CharField(read_only=True, source='audit_object.object_type')
    object_name = serializers.CharField(read_only=True, source='audit_object.object_name')

    class Meta:
        model = AuditLog
        fields = [
            'id',
            'object_id',
            'object_type',
            'object_name',
            'operation_type',
            'operation_name',
            'operation_result',
            'operation_time',
            'user_id',
            'object_changes',
        ]


class AuditSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditSession
        fields = [
            'id',
            'user_id',
            'login_result',
            'login_time',
            'login_details',
        ]
