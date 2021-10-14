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

"""Fill DB methods"""
# pylint: disable=invalid-name

import random
from collections import defaultdict
from copy import deepcopy

import allure

from tests.api.steps.common import assume_step
from tests.api.testdata.getters import get_endpoint_data, get_object_data
from tests.api.utils.api_objects import Request, ExpectedResponse
from tests.api.utils.endpoints import Endpoints
from tests.api.utils.fake_data import build_schema_by_json
from tests.api.utils.methods import Methods
from tests.api.utils.types import (
    get_fields,
    Field,
    is_fk_field,
    ForeignKeyM2M,
    ForeignKey,
    get_field_name_by_fk_dataclass,
)


# pylint: disable=too-few-public-methods
from tests.api.utils.api_objects import ADCMTestApiWrapper


class DbFiller:
    """Utils to prepare data in DB before test"""

    __slots__ = ("adcm", "_available_fkeys", "_used_fkeys")

    def __init__(self, adcm: ADCMTestApiWrapper):
        self.adcm = adcm
        self._available_fkeys = defaultdict(set)
        self._used_fkeys = {}

    @allure.step("Generate valid request data")
    def generate_valid_request_data(self, endpoint: Endpoints, method: Methods) -> dict:
        """
        Return valid request body and url params for endpoint and method combination
        """
        # POST
        if method == Methods.POST:
            return {
                "data": self._get_or_create_data_for_endpoint(
                    endpoint=endpoint,
                    force=True,
                    prepare_data_only=True,
                )[0],
                "url_params": {},
            }
        # LIST
        if method == Methods.LIST:
            self._get_or_create_multiple_data_for_endpoint(endpoint=endpoint, count=3)
            return {"data": None, "url_params": {}}

        full_item = get_object_data(
            adcm=self.adcm,
            endpoint=endpoint,
            object_id=self._get_or_create_data_for_endpoint(endpoint=endpoint)[0]['id'],
        )
        # GET, DELETE
        if method in (Methods.GET, Methods.DELETE):
            return {"data": None, "url_params": {}, "object_id": full_item["id"]}
        # PUT, PATCH
        if method in (Methods.PUT, Methods.PATCH):
            changed_fields = {}
            for field in get_fields(endpoint.data_class, predicate=lambda x: x.changeable):
                if isinstance(field.f_type, ForeignKey):
                    fk_data = self._get_or_create_data_for_endpoint(
                        endpoint=Endpoints.get_by_data_class(field.f_type.fk_link), force=True
                    )
                    if isinstance(field.f_type, ForeignKeyM2M):
                        changed_fields[field.name] = [{'id': el["id"]} for el in fk_data]
                    else:
                        changed_fields[field.name] = fk_data[0]["id"]
                elif field.name != "id":
                    changed_fields[field.name] = self._generate_field_value(
                        field=field, old_value=full_item[field.name]
                    )
            result = {
                "full_item": full_item.copy(),
                "changed_fields": changed_fields,
                "url_params": {},
                "object_id": full_item["id"],
            }
            full_item.update(changed_fields)
            result["data"] = full_item
            return result
        raise ValueError(f"No such method {method}")

    def _get_or_create_data_for_endpoint(self, endpoint: Endpoints, force=False, prepare_data_only=False):
        """
        Get data for endpoint with data preparation
        """

        for data_class in endpoint.data_class.predefined_dependencies:
            # If this is 'object' endpoint (for example, group-config/{id}/host)
            # we don't force create object and try to get one (first) of current created
            if f"{Endpoints.get_by_data_class(data_class).path}/{{id}}" in endpoint.path:
                endpoint_data = self._get_or_create_data_for_endpoint(endpoint=Endpoints.get_by_data_class(data_class))
                endpoint.path = endpoint.path.format(id=str(endpoint_data[0]["id"]))
            # else force create depended endpoint object
            else:
                self._get_or_create_data_for_endpoint(endpoint=Endpoints.get_by_data_class(data_class), force=True)

        if force and not prepare_data_only and Methods.POST not in endpoint.methods:
            if current_ep_data := get_endpoint_data(adcm=self.adcm, endpoint=endpoint):
                return current_ep_data
            raise ValueError(
                f"Force data creation is not available for {endpoint.path} and there is no any existing data"
            )

        if not force and (current_ep_data := get_endpoint_data(adcm=self.adcm, endpoint=endpoint)):
            # try to fetch data from current endpoint
            return current_ep_data

        data = self._prepare_data_for_object_creation(endpoint=endpoint, force=force)

        for data_class in endpoint.data_class.implicitly_depends_on:
            self._get_or_create_data_for_endpoint(endpoint=Endpoints.get_by_data_class(data_class), force=force)

        if not prepare_data_only:
            response = self.adcm.exec_request(
                request=Request(endpoint=endpoint, method=Methods.POST, data=data),
                expected_response=ExpectedResponse(status_code=Methods.POST.value.default_success_code),
            )
            return [response.json()]
        return [data]

    def _prepare_field_value_for_object_creation(self, field, force=False):
        if is_fk_field(field):
            fk_endpoint = Endpoints.get_by_data_class(field.f_type.fk_link)
            fk_data = None
            if "{id}" not in fk_endpoint.path:
                fk_data = get_endpoint_data(adcm=self.adcm, endpoint=fk_endpoint)
            if not fk_data or force:
                fk_data = self._get_or_create_data_for_endpoint(endpoint=fk_endpoint, force=force)
            return self._choose_fk_field_value(field=field, fk_data=fk_data)
        return self._generate_field_value(field=field)

    def _solve_field_relations(self, endpoint: Endpoints, data: dict, field: Field, force=False):
        """
        If field has relations, relate logic should be described in this place
        """
        _data = deepcopy(data)
        related_field_name = field.f_type.relates_on.field.name
        if not field.f_type.relates_on.data_class:
            if related_field_name not in _data:
                _data[related_field_name] = self._prepare_field_value_for_object_creation(
                    field=field.f_type.relates_on.field, force=force
                )

        if endpoint == Endpoints.GroupConfig:
            if field.name == "object_id":
                field.f_type.fk_link = Endpoints.get_by_path(_data[related_field_name]).data_class

        elif endpoint == Endpoints.ConfigLog:
            # Skip initial ADCM object because ADCM config object has validation rules
            if _data[related_field_name] == 1:
                _data[related_field_name] = 2
            if field.name in ["config", "attr"]:
                current_config_log = [data for data in get_endpoint_data(adcm=self.adcm, endpoint=endpoint)
                                      if data[related_field_name] == _data[related_field_name]][-1]
                field.f_type.schema = build_schema_by_json(current_config_log[field.name])

        else:
            raise NotImplementedError(f"Relations logic needs to be implemented for {endpoint} for field {field.name}")

        return _data, field

    def _prepare_data_for_object_creation(self, endpoint: Endpoints = None, force=False):
        data = {}
        for field in get_fields(data_class=endpoint.data_class, predicate=lambda x: x.postable):
            if field.name in data:
                continue
            if field.f_type.relates_on:
                data_with_relates, field = self._solve_field_relations(endpoint, data, field, force)
                data.update(data_with_relates)
            data[field.name] = self._prepare_field_value_for_object_creation(field, force)
        return data

    def _get_or_create_multiple_data_for_endpoint(self, endpoint: Endpoints, count: int):
        """
        Method for multiple data creation for given endpoint.
        For each object new object chain will be created.
        If endpoint does not allow data creation of any kind (POST, indirect creation, etc.)
        method will proceed without data creation or errors
        IMPORTANT: Class context _available_fkeys and _used_fkeys
                   will be relevant only for the last object in set
        """
        for data_class in endpoint.data_class.predefined_dependencies:
            if f"{Endpoints.get_by_data_class(data_class).path}/{{id}}" in endpoint.path:
                endpoint_data = self._get_or_create_data_for_endpoint(endpoint=Endpoints.get_by_data_class(data_class))
                endpoint.path = endpoint.path.format(id=str(endpoint_data[0]["id"]))
            else:
                self._get_or_create_data_for_endpoint(endpoint=Endpoints.get_by_data_class(data_class), force=True)
        current_ep_data = get_endpoint_data(adcm=self.adcm, endpoint=endpoint)
        if len(current_ep_data) < count:
            for _ in range(count - len(current_ep_data)):
                # clean up context before generating new element
                self._available_fkeys = defaultdict(set)
                self._used_fkeys = {}
                self._get_or_create_data_for_endpoint(
                    endpoint=endpoint,
                    force=True,
                )
                if len(get_endpoint_data(adcm=self.adcm, endpoint=endpoint)) > count:
                    break

    @staticmethod
    def _generate_field_value(field: Field, old_value=None):
        """Generate field value. If old_value is passed new value will be generated"""
        if old_value is not None:
            return field.f_type.generate_new(old_value=old_value)
        return field.f_type.generate()

    def _choose_fk_field_value(self, field: Field, fk_data: list):
        """Choose a random fk value for the specified field"""
        if isinstance(field.f_type, ForeignKey):
            fk_class_name = field.f_type.fk_link.__name__
            if fk_class_name in self._available_fkeys:
                new_fk = False
                fk_vals = self._available_fkeys[fk_class_name]
            else:
                new_fk = True
                fk_vals = {el["id"] for el in fk_data}

            if isinstance(field.f_type, ForeignKeyM2M):
                keys = random.sample(fk_vals, random.randint(1, len(fk_vals)))
                result = [{'id': el} for el in keys]
                # we do not save values for M2M Fk to used keys due to the fact
                # that we have no idea how to properly use it
                self._available_fkeys[fk_class_name].update(keys)
                if new_fk:
                    self._add_child_fk_values_to_available_fkeys(fk_ids=keys, fk_data_class=field.f_type.fk_link)
            else:
                key = random.choice(list(fk_vals))
                result = key
                self._used_fkeys[fk_class_name] = key
                self._available_fkeys[fk_class_name].add(key)
                if new_fk:
                    self._add_child_fk_values_to_available_fkeys(fk_ids=[key], fk_data_class=field.f_type.fk_link)
            return result
        # if field is not FK
        raise ValueError("Argument field is not FKey!")

    def _add_child_fk_values_to_available_fkeys(self, fk_ids: list, fk_data_class):
        """Add information about child FK values to metadata for further consistency"""
        for child_fk_field in get_fields(data_class=fk_data_class, predicate=is_fk_field):
            fk_field_name = get_field_name_by_fk_dataclass(
                data_class=fk_data_class, fk_data_class=child_fk_field.f_type.fk_link
            )
            for fk_id in fk_ids:
                fk_data = get_object_data(
                    adcm=self.adcm,
                    endpoint=Endpoints.get_by_data_class(fk_data_class),
                    object_id=fk_id,
                )
                if isinstance(child_fk_field.f_type, ForeignKeyM2M):
                    self._available_fkeys[child_fk_field.f_type.fk_link.__name__].update(
                        [el["id"] for el in fk_data[fk_field_name]]
                    )
                elif isinstance(child_fk_field.f_type, ForeignKey):
                    self._available_fkeys[child_fk_field.f_type.fk_link.__name__].add(fk_data[fk_field_name])

    @allure.step("Generate new value for unchangeable FK_field")
    def generate_new_value_for_unchangeable_fk_field(self, f_type, current_field_value):
        """Generate new value for unchangeable fk fields"""
        if not isinstance(f_type, ForeignKey):
            raise ValueError("Field type is not ForeignKey")
        new_objects = get_endpoint_data(self.adcm, Endpoints.get_by_data_class(f_type.fk_link))
        if len(new_objects) == 1:
            with assume_step(f'Data creation is not available for {f_type.fk_link}', exception=ValueError):
                new_objects = self._get_or_create_data_for_endpoint(
                    endpoint=Endpoints.get_by_data_class(f_type.fk_link), force=True
                )
        valid_new_objects = [obj for obj in new_objects if obj["id"] != current_field_value]
        if valid_new_objects:
            return valid_new_objects[0]["id"]
        with allure.step("Failed to create new data. Returning a non-existent object"):
            return 42
