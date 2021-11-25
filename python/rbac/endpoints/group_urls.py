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

from django.urls import path, include
from rest_framework.routers import SimpleRouter, Route
from rest_framework_extensions.routers import ExtendedDefaultRouter


from .group import GroupViewSet, GroupRoleViewSet


class GroupRouter(SimpleRouter):
    """Router for User"""

    routes = [
        Route(
            url='^{prefix}$',
            mapping={'get': 'list', 'post': 'create'},
            name='{basename}-list',
            detail=False,
            initkwargs={'suffix': 'List'},
        ),
        Route(
            url='^{prefix}/{lookup}/$',
            mapping={
                'get': 'retrieve',
                'put': 'update',
                'patch': 'partial_update',
                'delete': 'destroy',
            },
            name='{basename}-detail',
            detail=True,
            initkwargs={'suffix': 'Detail'},
        ),
    ]


# router = GroupRouter()
router = ExtendedDefaultRouter()
router.register('', GroupViewSet, basename='group')

role_urls = [
    path('', GroupRoleViewSet.as_view({'get': 'list', 'post': 'create'}), name='group-role-list'),
    path(
        '<int:role_id>/',
        GroupRoleViewSet.as_view({'get': 'retrieve', 'delete': 'destroy'}),
        name='group-role-detail',
    ),
]

urlpatterns = router.urls
# urlpatterns.append(path('<int:id>/role/', include(role_urls)))
# urlpatterns = [
#     path('', include(router.urls)),
#     path('<int:id>/role/', include(role_urls)),
# ]
