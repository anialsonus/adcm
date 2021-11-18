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

"""ViewSet and Serializers for Role"""

from rest_flex_fields.serializers import FlexFieldsSerializerMixin
from rest_framework import serializers

from rbac.models import Role
from rbac.viewsets import ModelPermViewSet
from .user.serializers import PermissionSerializer


class RoleSerializer(FlexFieldsSerializerMixin, serializers.HyperlinkedModelSerializer):
    """Role serializer"""

    permissions = PermissionSerializer(many=True)
    childs = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = (
            'id',
            'name',
            'description',
            'permissions',
            'childs',
            'url',
        )
        extra_kwargs = {
            'url': {'view_name': 'rbac:role-detail', 'lookup_field': 'id'},
        }

    def get_childs(self, obj):
        return RoleSerializer(obj.childs.all(), many=True, context=self.context).data


# pylint: disable=too-many-ancestors
class RoleViewSet(ModelPermViewSet):
    """Role View Set"""

    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    lookup_field = 'id'
    filterset_fields = ['id', 'name']
    ordering_fields = ['id', 'name']
