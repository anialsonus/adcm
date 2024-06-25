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

from abc import ABC
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable, Iterable, ParamSpec

from rest_framework.response import Response
from typing_extensions import Self

from audit.alt.core import AuditHookFunc, Hooks, OperationAuditContext, RetrieveAuditObjectFunc
from audit.alt.hooks import (
    cleanup_changes,
    collect_meta,
    detect_request_user,
    mark_object_as_deleted_on_success,
    only_on_success,
    retriever_as_hook,
    set_api_operation_result,
)
from audit.alt.object_retrievers import ignore_object_search
from audit.models import AuditLogOperationType

P = ParamSpec("P")

AUDITED_HTTP_METHODS = frozenset(("POST", "DELETE", "PUT", "PATCH"))


class APIOperationAuditContext(OperationAuditContext):
    DEFAULT_HOOKS = Hooks(pre_call=(detect_request_user, collect_meta), on_collect=(set_api_operation_result,))


@dataclass(slots=True, frozen=True)
class AuditedEndpointConfig:
    operation_type: AuditLogOperationType
    operation_name: str
    retrieve_object_func: RetrieveAuditObjectFunc
    hooks: Hooks


class AuditEndpointsRegistry:
    """
    Registry of view functions that should be audited.
    Used to match caller func and audit configuration in runtime (usually middleware).

    Key extraction is bound to usages, so it may have to be adjusted/extended in the future.
    """

    __slots__ = ("_endpoints",)

    def __init__(self):
        self._endpoints: dict[str, AuditedEndpointConfig] = {}

    def register(self, func: Callable, config: AuditedEndpointConfig) -> None:
        key = f"{getattr(func, '__module__', '-')}:{func.__qualname__}"
        self._endpoints[key] = config

    def find_for_view(self, http_method: str, view_func: Any) -> AuditedEndpointConfig | None:
        # view_func is not just simple Callable, it's special func prepared by Django's middleware system.
        # __qualname__ of view_func doesn't specify method (because it's View, not API method itself)
        method_name = getattr(view_func, "actions", {}).get(http_method.lower(), "")
        key = f"{getattr(view_func, '__module__', '-')}:{view_func.__qualname__}.{method_name}".rstrip(".")
        return self._endpoints.get(key)


@lru_cache(maxsize=1)
def get_endpoints_registry() -> AuditEndpointsRegistry:
    return AuditEndpointsRegistry()


class GenericAPIAuditDecorator:
    """
    Decorator to wrap ViewSet's functions that should be audited.
    Adds function to registry and returns function without changes.
    Additional hooks may be configured after instantiation.
    """

    def __init__(self, name: str, type_: AuditLogOperationType, object_: RetrieveAuditObjectFunc):
        self.operation_type = type_
        self.operation_name = name
        self.retrieve_object_func = object_
        self.extra_pre_call_hooks = []
        self.extra_on_collect_hooks = []

        self._registry = get_endpoints_registry()

    def __call__(self, func: Callable[P, Response]) -> Callable[P, Response]:
        endpoint_config = AuditedEndpointConfig(
            operation_type=self.operation_type,
            operation_name=self.operation_name,
            retrieve_object_func=self.retrieve_object_func,
            hooks=Hooks(pre_call=tuple(self.extra_pre_call_hooks), on_collect=tuple(self.extra_on_collect_hooks)),
        )

        self._registry.register(func=func, config=endpoint_config)

        return func


class TypedAuditDecorator(GenericAPIAuditDecorator, ABC):
    OPERATION_TYPE: AuditLogOperationType

    def __init__(self, name: str, object_: RetrieveAuditObjectFunc):
        if not getattr(self, "OPERATION_TYPE", None):
            message = "OPERATION_TYPE should be specified"
            raise ValueError(message)

        super().__init__(name=name, type_=self.OPERATION_TYPE, object_=object_)

    def attach_hooks(
        self,
        pre_call: AuditHookFunc | Iterable[AuditHookFunc] = (),
        on_collect: AuditHookFunc | Iterable[AuditHookFunc] = (),
    ) -> Self:
        self.extra_pre_call_hooks.extend(pre_call if not callable(pre_call) else (pre_call,))
        self.extra_on_collect_hooks.extend(on_collect if not callable(on_collect) else (on_collect,))

        return self


class audit_create(TypedAuditDecorator):  # noqa: N801
    OPERATION_TYPE = AuditLogOperationType.CREATE


class audit_update(TypedAuditDecorator):  # noqa: N801
    OPERATION_TYPE = AuditLogOperationType.UPDATE

    def track_changes(self, before: AuditHookFunc, after: AuditHookFunc) -> Self:
        """Shouldn't be called more than 1 time, isn't adopted for that"""

        self.extra_pre_call_hooks.append(before)
        self.extra_on_collect_hooks.append(only_on_success(after))
        self.extra_on_collect_hooks.append(cleanup_changes)

        return self


class audit_delete(TypedAuditDecorator):  # noqa: N801
    OPERATION_TYPE = AuditLogOperationType.DELETE

    def __init__(self, name: str, object_: RetrieveAuditObjectFunc, removed_on_success: bool = False):
        retrieve_func, pre_hooks, collect_hooks = object_, (), ()
        if removed_on_success:
            retrieve_func = ignore_object_search
            pre_hooks = (retriever_as_hook(object_),)
            collect_hooks = (mark_object_as_deleted_on_success,)

        super().__init__(name=name, object_=retrieve_func)

        self.extra_pre_call_hooks.extend(pre_hooks)
        self.extra_on_collect_hooks.extend(collect_hooks)
