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
import copy
import json
from abc import ABC, abstractmethod
from collections import OrderedDict, defaultdict
from copy import deepcopy
from operator import attrgetter
from typing import Any

from cm.adcm_config.config import get_default
from cm.errors import AdcmEx
from cm.models import (
    Action,
    ADCMEntity,
    ConfigLog,
    GroupConfig,
    Prototype,
    PrototypeConfig,
)
from cm.variant import get_variant
from django.db.models import QuerySet
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK


class Field(ABC):  # pylint: disable=too-many-instance-attributes
    def __init__(self, prototype_config: PrototypeConfig, object_: ADCMEntity | GroupConfig):
        self.object_ = object_
        self.is_group_config = False

        if isinstance(object_, GroupConfig):
            self.is_group_config = True
            self.object_ = object_.object

        self.prototype_config = prototype_config

        self.name = prototype_config.name
        self.title = prototype_config.display_name
        self.description = prototype_config.description
        self.limits = self.prototype_config.limits
        self.required = self.prototype_config.required

    @property
    @abstractmethod
    def type(self) -> str:
        ...

    @property
    def is_read_only(self) -> bool:
        if not self.limits:
            return False

        readonly = self.limits.get("read_only", [])
        writeable = self.limits.get("writable", [])

        if readonly == "any" or self.object_.state in readonly:
            return True

        if writeable == "any":
            return False

        if writeable and self.object_.state not in writeable:
            return True

        return False

    @property
    def is_advanced(self) -> bool:
        return self.prototype_config.ui_options.get("advanced", False)

    @property
    def is_invisible(self) -> bool:
        if self.prototype_config.name == "__main_info":
            return True

        return self.prototype_config.ui_options.get("invisible", False)

    @property
    def activation(self) -> dict | None:
        return None

    @property
    def synchronization(self) -> dict | None:
        if not self.is_group_config:
            return None

        is_allow_change = self.prototype_config.group_customization
        if is_allow_change is None:
            is_allow_change = self.object_.prototype.config_group_customization

        return {"isAllowChange": is_allow_change}

    @property
    def null_value(self) -> list | dict | None:
        return None

    @property
    def is_secret(self) -> bool:
        return False

    @property
    def string_extra(self) -> dict | None:
        return None

    @property
    def enum_extra(self) -> dict | None:
        return None

    @property
    def default(self) -> Any:
        return get_default(conf=self.prototype_config, prototype=self.prototype_config.prototype)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "type": self.type,
            "description": self.description,
            "default": self.default,
            "readOnly": self.is_read_only,
            "adcmMeta": {
                "isAdvanced": self.is_advanced,
                "isInvisible": self.is_invisible,
                "activation": self.activation,
                "synchronization": self.synchronization,
                "nullValue": self.null_value,
                "isSecret": self.is_secret,
                "stringExtra": self.string_extra,
                "enumExtra": self.enum_extra,
            },
        }


class Boolean(Field):
    type = "boolean"

    def to_dict(self) -> dict:
        data = super().to_dict()

        if not self.required:
            return {"oneOf": [data, {"type": "null"}]}

        return data


class Float(Field):
    type = "number"

    def to_dict(self) -> dict:
        data = super().to_dict()

        if "min" in self.limits:
            data.update({"minimum": self.limits["min"]})

        if "max" in self.limits:
            data.update({"maximum": self.limits["max"]})

        if not self.required:
            return {"oneOf": [data, {"type": "null"}]}

        return data


class Integer(Field):
    type = "integer"

    def to_dict(self) -> dict:
        data = super().to_dict()

        if "min" in self.limits:
            data.update({"minimum": self.limits["min"]})

        if "max" in self.limits:
            data.update({"maximum": self.limits["max"]})

        if not self.required:
            return {"oneOf": [data, {"type": "null"}]}

        return data


class String(Field):
    type = "string"

    @property
    def string_extra(self) -> dict | None:
        return {"isMultiline": False}

    def to_dict(self) -> dict:
        data = super().to_dict()

        if self.required:
            data.update({"minLength": 1})
        else:
            return {"oneOf": [data, {"type": "null"}]}

        return data


class Password(String):
    @property
    def is_secret(self) -> bool:
        return True


class Text(String):
    @property
    def string_extra(self) -> dict | None:
        return {"isMultiline": True}


class SecretText(Text):
    @property
    def is_secret(self) -> bool:
        return True


class File(Text):
    pass


class SecretFile(SecretText):
    pass


class Json(Field):
    type = "string"

    @property
    def string_extra(self) -> dict | None:
        return {"isMultiline": True}

    def to_dict(self) -> dict:
        data = super().to_dict()

        data.update({"format": "json", "default": json.dumps(data["default"])})

        if self.required:
            data.update({"minLength": 1})

        if not self.required:
            return {"oneOf": [data, {"type": "null"}]}

        return data


class Map(Field):
    type = "object"

    @property
    def null_value(self) -> list | dict | None:
        return {}

    @property
    def default(self) -> Any:
        default = super().default

        if default is None:
            return {}

        return default

    def to_dict(self) -> dict:
        data = super().to_dict()

        data.update({"additionalProperties": True, "properties": {}})

        if self.required:
            data.update({"minProperties": 1})

        return data


class SecretMap(Map):
    @property
    def is_secret(self) -> bool:
        return True

    @property
    def null_value(self) -> list | dict | None:
        return None


class Structure(Field):
    def __init__(self, prototype_config: PrototypeConfig, object_: ADCMEntity | GroupConfig):
        super().__init__(prototype_config=prototype_config, object_=object_)

        self.yspec = self.limits["yspec"]

    @staticmethod
    def _get_schema_type(type_: str) -> str:
        match type_:
            case "list":
                return "array"
            case "dict":
                return "object"
            case "bool":
                return "boolean"
            case "string":
                return "string"
            case "int":
                return "integer"
            case "float":
                return "number"
            case _:
                raise NotImplementedError

    @property
    def type(self) -> str:
        return self._get_schema_type(type_=self.yspec["root"]["match"])

    @property
    def default(self) -> Any:
        default = super().default

        if default is None:
            if self.type == "array":
                return []
            if self.type == "object":
                return {}

        return default

    def _get_inner(self, title: str = "", **kwargs) -> dict:
        type_ = self._get_schema_type(type_=kwargs["match"])

        data = {
            "type": type_,
            "title": title,
            "description": "",
            "default": None,
            "readOnly": self.is_read_only,
            "adcmMeta": {
                "isAdvanced": self.is_advanced,
                "isInvisible": self.is_invisible,
                "activation": self.activation,
                "synchronization": None,
                "nullValue": self.null_value,
                "isSecret": self.is_secret,
                "stringExtra": self.string_extra,
                "enumExtra": self.enum_extra,
            },
        }

        if type_ == "array":
            data.update({"items": self._get_inner(**self.yspec[kwargs["item"]]), "default": []})

        elif type_ == "object":
            data.update(
                {
                    "additionalProperties": False,
                    "properties": {},
                    "required": kwargs.get("required_items", []),
                    "default": {},
                }
            )

            for item_key, item_value in kwargs["items"].items():
                data["properties"][item_key] = self._get_inner(title=item_key, **self.yspec[item_value])

        return data

    def to_dict(self) -> dict:
        data = super().to_dict()

        type_ = self.type

        if type_ == "array":
            item = self.yspec["root"]["item"]
            data["items"] = self._get_inner(**self.yspec[item])

            if self.required:
                data.update({"minItems": 1})

        if type_ == "object":
            data.update(
                {
                    "additionalProperties": False,
                    "properties": {},
                    "required": self.yspec["root"].get("required_items", []),
                }
            )
            items = self.yspec["root"]["items"]

            for item_key, item_value in items.items():
                data["properties"][item_key] = self._get_inner(**self.yspec[item_value])

            if self.required:
                data.update({"minProperties": 1})

        return data


class Group(Field):
    type = "object"

    def __init__(
        self,
        prototype_config: PrototypeConfig,
        object_: ADCMEntity | GroupConfig,
        group_fields: QuerySet[PrototypeConfig],
    ):
        super().__init__(prototype_config=prototype_config, object_=object_)
        self.group_fields = group_fields
        self.root_object = object_

    @property
    def activation(self) -> dict | None:
        if "activatable" in self.limits:
            return {"isAllowChange": not self.is_read_only}

        return None

    @property
    def synchronization(self) -> dict | None:
        data = super().synchronization

        if "activatable" not in self.limits:
            return None

        return data

    def get_properties(self) -> dict:
        data = {"properties": OrderedDict(), "required": [], "default": {}}

        for field in self.group_fields:
            data["properties"][field.subname] = get_field(prototype_config=field, object_=self.root_object).to_dict()
            data["required"].append(field.subname)

        return data

    def to_dict(self) -> dict:
        data = super().to_dict()
        data["additionalProperties"] = False
        data.update(**self.get_properties())

        return data


class List(Field):
    type = "array"

    @property
    def null_value(self) -> list | dict | None:
        return []

    @property
    def default(self) -> Any:
        default = super().default

        if default is None:
            return []

        return default

    def to_dict(self) -> dict:
        data = super().to_dict()

        data.update(
            {
                "items": {
                    "type": "string",
                    "title": "",
                    "description": "",
                    "default": None,
                    "readOnly": self.is_read_only,
                    "adcmMeta": {
                        "isAdvanced": False,
                        "isInvisible": False,
                        "activation": None,
                        "synchronization": None,
                        "nullValue": None,
                        "isSecret": False,
                        "stringExtra": None,
                        "enumExtra": None,
                    },
                },
            }
        )

        if self.required:
            data.update({"minItems": 1})

        if not self.required:
            return {"oneOf": [data, {"type": "null"}]}

        return data


class Option(Field):
    type = "enum"

    @property
    def string_extra(self) -> dict | None:
        return {"isMultiline": True}

    @property
    def enum_extra(self) -> dict | None:
        return {"labels": list(self.limits["option"].keys())}

    def to_dict(self) -> dict:
        data = super().to_dict()

        data.pop("type")
        data.update({"enum": [self.limits["option"][key] for key in self.enum_extra["labels"]]})

        return data


class Variant(Field):
    type = "string"

    def _get_variant(self) -> list | None:
        config = ConfigLog.objects.get(id=self.object_.config.current).config
        return get_variant(obj=self.object_, conf=config, limits=self.limits)

    @property
    def string_extra(self) -> dict | None:
        string_extra = {"isMultiline": False}

        if not self.limits["source"]["strict"]:
            string_extra.update({"suggestions": self._get_variant()})

        return string_extra

    def to_dict(self) -> dict:
        data = super().to_dict()

        if self.limits["source"]["strict"]:
            data.pop("type")
            data.update({"enum": self._get_variant()})

        if self.required:
            data.update({"minLength": 1})

        return data


def get_field(
    prototype_config: PrototypeConfig,
    object_: ADCMEntity,
    group_fields: QuerySet[PrototypeConfig] | None = None,
):
    match prototype_config.type:
        case "boolean":
            field = Boolean(prototype_config=prototype_config, object_=object_)
        case "float":
            field = Float(prototype_config=prototype_config, object_=object_)
        case "integer":
            field = Integer(prototype_config=prototype_config, object_=object_)
        case "file":
            field = File(prototype_config=prototype_config, object_=object_)
        case "json":
            field = Json(prototype_config=prototype_config, object_=object_)
        case "password":
            field = Password(prototype_config=prototype_config, object_=object_)
        case "secretfile":
            field = SecretFile(prototype_config=prototype_config, object_=object_)
        case "secrettext":
            field = SecretText(prototype_config=prototype_config, object_=object_)
        case "string":
            field = String(prototype_config=prototype_config, object_=object_)
        case "text":
            field = Text(prototype_config=prototype_config, object_=object_)
        case "map":
            field = Map(prototype_config=prototype_config, object_=object_)
        case "secretmap":
            field = SecretMap(prototype_config=prototype_config, object_=object_)
        case "structure":
            field = Structure(prototype_config=prototype_config, object_=object_)
        case "group":
            field = Group(prototype_config=prototype_config, object_=object_, group_fields=group_fields)
        case "list":
            field = List(prototype_config=prototype_config, object_=object_)
        case "option":
            field = Option(prototype_config=prototype_config, object_=object_)
        case "variant":
            field = Variant(prototype_config=prototype_config, object_=object_)
        case _:
            raise TypeError

    return field


def get_config_schema(
    object_: ADCMEntity | GroupConfig, prototype_configs: QuerySet[PrototypeConfig] | list[PrototypeConfig]
) -> dict:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Configuration",
        "description": "",
        "readOnly": False,
        "adcmMeta": {
            "isAdvanced": False,
            "isInvisible": False,
            "activation": None,
            "synchronization": None,
            "nullValue": None,
            "isSecret": False,
            "stringExtra": None,
            "enumExtra": None,
        },
        "type": "object",
        "properties": OrderedDict(),
        "additionalProperties": False,
        "required": [],
    }

    if not prototype_configs:
        return schema

    prototype_configs = sorted(prototype_configs, key=attrgetter("pk"))

    top_fields = [pc for pc in prototype_configs if pc.subname == ""]

    for field in top_fields:
        if field.type == "group":
            group_fields = [
                pc
                for pc in prototype_configs
                if pc.name == field.name and pc.prototype == field.prototype and pc.type != "group"
            ]
            item = get_field(prototype_config=field, object_=object_, group_fields=group_fields).to_dict()
        else:
            item = get_field(prototype_config=field, object_=object_).to_dict()

        schema["properties"][field.name] = item
        schema["required"].append(field.name)

    return schema


class ConfigSchemaMixin:
    @action(methods=["get"], detail=True, url_path="config-schema", url_name="config-schema")
    def config_schema(self, request, *args, **kwargs) -> Response:  # pylint: disable=unused-argument
        instance = self.get_object()
        schema = get_config_schema(
            object_=instance,
            prototype_configs=PrototypeConfig.objects.filter(prototype=instance.prototype, action=None).order_by("pk"),
        )

        return Response(data=schema, status=HTTP_200_OK)


def convert_attr_to_adcm_meta(attr: dict) -> dict:
    attr = deepcopy(attr)
    adcm_meta = defaultdict(dict)
    attr.pop("custom_group_keys", None)
    group_keys = attr.pop("group_keys", {})

    for key, value in attr.items():
        adcm_meta[f"/{key}"].update({"isActive": value["active"]})

    for key, value in group_keys.items():
        if isinstance(value, dict):
            if isinstance(value["value"], bool):
                adcm_meta[f"/{key}"].update({"isSynchronized": value["value"]})
            for sub_key, sub_value in value["fields"].items():
                adcm_meta[f"/{key}/{sub_key}"].update({"isSynchronized": sub_value})
        else:
            adcm_meta[f"/{key}"].update({"isSynchronized": value})

    return adcm_meta


def convert_adcm_meta_to_attr(adcm_meta: dict) -> dict:
    attr = defaultdict(dict)
    try:
        for key, value in adcm_meta.items():
            _, key, *sub_key = key.split("/")

            if sub_key:
                sub_key = sub_key[0]

                if key not in attr["group_keys"]:
                    attr["group_keys"].update({key: {"value": None, "fields": {}}})

                attr["group_keys"][key]["fields"].update({sub_key: value["isSynchronized"]})
            else:
                if "isSynchronized" in value and "isActive" in value:
                    # activatable group in config-group
                    attr[key].update({"active": value["isActive"]})
                    attr["group_keys"].update({key: {"value": value["isSynchronized"], "fields": {}}})
                elif "isActive" in value:
                    # activatable group not in config-group
                    attr[key].update({"active": value["isActive"]})
                else:
                    # non-group root field in config-group
                    attr["group_keys"].update({key: value["isSynchronized"]})
    except (KeyError, ValueError):
        return adcm_meta

    return attr


def represent_json_type_as_string(prototype: Prototype, value: dict, action_: Action | None = None) -> dict:
    value = copy.deepcopy(value)

    for name, sub_name in PrototypeConfig.objects.filter(prototype=prototype, type="json", action=action_).values_list(
        "name", "subname"
    ):
        if name not in value or (sub_name and sub_name not in value[name]):
            continue

        if sub_name:
            value[name][sub_name] = json.dumps(value[name][sub_name])
        else:
            value[name] = json.dumps(value[name])

    return value


def represent_string_as_json_type(
    prototype_configs: QuerySet[PrototypeConfig] | list[PrototypeConfig], value: dict
) -> dict:
    value = copy.deepcopy(value)

    for prototype_config in prototype_configs:
        name = prototype_config.name
        sub_name = prototype_config.subname

        if name not in value or sub_name not in value[name]:
            continue

        try:
            if sub_name:
                value[name][sub_name] = json.loads(value[name][sub_name])
            else:
                value[name] = json.loads(value[name])
        except json.JSONDecodeError:
            raise AdcmEx(
                code="CONFIG_KEY_ERROR",
                msg=f"The '{name}/{sub_name}' key must be in the json format.",
            ) from None
        except TypeError:
            raise AdcmEx(
                code="CONFIG_KEY_ERROR",
                msg=f"The '{name}/{sub_name}' key must be a string type.",
            ) from None

    return value
