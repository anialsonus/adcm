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

from rest_framework.permissions import DjangoObjectPermissions


class ClusterPermissions(DjangoObjectPermissions):
    perms_map = {
        "GET": [],
        "OPTIONS": [],
        "HEAD": [],
        "POST": ["%(app_label)s.add_%(model_name)s"],
        "PUT": ["%(app_label)s.change_%(model_name)s"],
        "PATCH": ["%(app_label)s.change_%(model_name)s"],
        "DELETE": ["%(app_label)s.delete_%(model_name)s"],
    }

    def has_permission(self, request, view) -> bool:
        if (
            view.action in ["destroy", "update", "partial_update", "ansible_config"]
            or view.action == "mapping"
            and request.method == "POST"
        ):
            return True

        return super().has_permission(request=request, view=view)

    def has_object_permission(self, request, view, obj) -> bool:
        if view.action == "mapping" and request.method == "POST":
            self.perms_map["POST"] = []
        elif view.action == "ansible_config" and request.method == "POST":
            self.perms_map["POST"] = ["%(app_label)s.change_%(model_name)s"]
        else:
            self.perms_map["POST"] = ["%(app_label)s.add_%(model_name)s"]

        return super().has_object_permission(request=request, view=view, obj=obj)
