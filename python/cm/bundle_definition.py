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

import hashlib
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

from django.conf import settings
from pydantic import BaseModel, Extra, Json  # pylint: disable=no-name-in-module

from cm.errors import AdcmEx
from cm.logger import logger
from cm.stack import (
    ANY,
    AVAILABLE,
    MASKING,
    MULTI_STATE,
    ON_FAIL,
    ON_SUCCESS,
    SET,
    STATE,
    STATES,
    UNAVAILABLE,
    UNSET,
    _deep_get,
    check_object_definition,
    check_upgrade,
    validate_name,
)

# pylint: disable=too-many-instance-attributes


DEFAULT_CONSTRAINT = [0, "+"]
DEFAULT_FROM_EDITION = ["community"]


class DefinitionFile(BaseModel):
    bundle_hash: str
    config: dict | list[dict]
    filename: str
    path: str


class DefinitionData(BaseModel):
    """Single definition divided into entities (list of python entities)"""

    definition_file: DefinitionFile
    prototypes: list = []
    actions: list = []
    sub_actions: list = []
    prototype_configs: list = []
    upgrades: list = []
    prototype_exports: list = []
    prototype_imports: list = []


class BaseData(BaseModel):
    _none_allowed_fields = ()
    _to_db_fields = set()

    # TODO: 1. prepare data; 2.Model.from_obj(data) to prevent misspells
    class Config:
        extra = Extra.forbid

    def _get_db_dict(self) -> dict:
        return self.dict(include=self._to_db_fields)

    @classmethod
    def _dict_get(cls, source: dict, key: str) -> tuple[Any, bool]:
        """returns (<value>, <is_legit_value>)"""
        if key in source:
            if source.get(key, None) is None:
                if key in cls._none_allowed_fields:
                    return None, True
                else:
                    return None, False

            return source[key], True

        return None, False

    @staticmethod
    def _get_display_name(source: dict, prototype: "PrototypeData"):
        if "display_name" in source:
            return source["display_name"]

        return prototype.name


class PrototypeData(BaseData):
    type: str
    parent: "PrototypeData" = None
    name: str
    path: str = ""
    display_name: str = ""
    version: str
    edition: str = "community"
    license: str = "absent"
    license_path: str | None = None
    license_hash: str | None = None
    required: bool = False
    shared: bool = False
    constraint: Json[list[str | int]] = DEFAULT_CONSTRAINT
    requires: Json[list] = []
    bound_to: Json[dict] = {}
    adcm_min_version: str | None = None
    description: str = ""
    monitoring: str = "active"
    config_group_customization: bool = False
    venv: str = "default"
    allow_maintenance_mode: bool = False

    @property
    def ref(self):
        return f"{self.type} \"{self.name}\" {self.version}"

    @classmethod
    def make(cls, source: dict, definition_data: DefinitionData) -> "PrototypeData":
        prototype = cls(
            name=source["name"],
            type=source["type"],
            path=definition_data.definition_file.path,
            version=source["version"],
        )

        value, legit = cls._dict_get(source=source, key="required")
        if legit:
            prototype.required = value
        value, legit = cls._dict_get(source=source, key="shared")
        if legit:
            prototype.shared = value
        value, legit = cls._dict_get(source=source, key="monitoring")
        if legit:
            prototype.monitoring = value
        value, legit = cls._dict_get(source=source, key="description")
        if legit:
            prototype.description = value
        value, legit = cls._dict_get(source=source, key="adcm_min_version")
        if legit:
            prototype.adcm_min_version = value
        value, legit = cls._dict_get(source=source, key="venv")
        if legit:
            prototype.venv = value
        value, legit = cls._dict_get(source=source, key="edition")
        if legit:
            prototype.edition = value
        value, legit = cls._dict_get(source=source, key="allow_maintenance_mode")
        if legit:
            prototype.allow_maintenance_mode = value

        prototype.display_name = cls._get_display_name(source=source, prototype=prototype)
        prototype.config_group_customization = cls.get_config_group_customization(
            source=source, prototype=prototype, definition_data=definition_data
        )

        if license_hash := cls.get_license_hash(
            source=source, prototype=prototype, definition_file=definition_data.definition_file
        ) != "absent" and prototype.type not in [
            "cluster",
            "service",
            "provider",
        ]:
            raise AdcmEx(
                "INVALID_OBJECT_DEFINITION",
                f"Invalid license definition in {prototype.ref}. License can be placed in cluster, service or provider",
            )

        value, legit = cls._dict_get(source=source, key="license")
        if legit and license_hash != "absent":
            prototype.license_path = source["license"]
            prototype.license_hash = license_hash

        return prototype

    @staticmethod
    def get_config_group_customization(
        source: dict, prototype: "PrototypeData", definition_data: DefinitionData
    ) -> bool:
        if not source:
            return False

        if "config_group_customization" not in source:
            cluster_prototype = None

            if prototype.type == "service":
                cluster_prototype = [i for i in definition_data.prototypes + [prototype] if i.type == "cluster"]
                if len(cluster_prototype) < 1:
                    logger.debug("Can't find cluster for service %s", prototype.name)
                elif len(cluster_prototype) > 1:
                    logger.debug("Found more than one cluster for service %s", prototype.name)
                else:
                    cluster_prototype = cluster_prototype[0]

            elif prototype.type == "component":
                cluster_prototype = prototype.parent

            if cluster_prototype:
                return cluster_prototype.config_group_customization

        return False

    @staticmethod
    def get_license_hash(source: dict, prototype: "PrototypeData", definition_file: DefinitionFile) -> str:
        if "license" not in source:
            return "absent"

        else:
            if source["license"][0:2] == "./":
                path = Path(settings.BUNDLE_DIR, definition_file.bundle_hash, prototype.path, source["license"])
            else:
                path = Path(settings.BUNDLE_DIR, definition_file.bundle_hash, definition_file.filename)

            license_file = None
            try:
                license_file = open(path, "r", encoding=settings.ENCODING_UTF_8)
            except FileNotFoundError as e:
                raise AdcmEx("CONFIG_TYPE_ERROR", f'"license file" "{path}" is not found ({prototype.ref})') from e
            except PermissionError as e:
                raise AdcmEx("CONFIG_TYPE_ERROR", f'"license file" "{path}" can not be open ({prototype.ref})') from e

            if license_file is not None:
                body = license_file.read()
                license_file.close()

                sha1 = hashlib.sha256()
                sha1.update(body.encode(settings.ENCODING_UTF_8))

                return sha1.hexdigest()

        return "absent"


class ActionData(BaseData):
    # prototype: PrototypeData
    prototype_ref: str  # TODO: questionable

    name: str
    display_name: str = ""
    description: str = ""
    ui_options: Json[dict] = {}

    type: str
    script: str = ""
    script_type: str = ""

    state_available: Json[list] = []
    state_unavailable: Json[list] = []
    state_on_success: str = ""
    state_on_fail: str = ""

    multi_state_available: Json[list] = ["any"]
    multi_state_unavailable: Json[list] = []
    multi_state_on_success_set: Json[list] = []
    multi_state_on_success_unset: Json[list] = []
    multi_state_on_fail_set: Json[list] = []
    multi_state_on_fail_unset: Json[list] = []

    params: Json[dict] = {}
    log_files: Json[list] = []

    hostcomponentmap: Json[list] = []
    allow_to_terminate: bool = False
    partial_execution: bool = False
    host_action: bool = False
    allow_in_maintenance_mode: bool = False

    venv: str = "default"

    # #field to link upgrade to action DO NOT USE IN DB  # TODO: remove comment when save_to_db() is done
    # upgrade_ref: str | None = None

    @property
    def ref(self):
        return f"Action \"{self.name}\" of proto \"{self.prototype_ref}\""

    @classmethod
    def make_bulk(
        cls, source: dict, prototype: PrototypeData, upgrade: Optional["UpgradeData"] = None
    ) -> list[tuple["ActionData", dict]]:
        source = deepcopy(source)

        if source.get("versions") is not None:
            source["type"] = "task"
            upgrade_name = source["name"]
            source["display_name"] = f"Upgrade: {upgrade_name}"

            if upgrade is not None:
                action_name = (
                    f"{prototype.name}_{prototype.version}_{prototype.edition}_upgrade_{upgrade_name}_"
                    f"{upgrade.min_version}_strict_{upgrade.min_strict}-{upgrade.max_version}_strict_"
                    f"{upgrade.min_strict}_editions-{'_'.join(upgrade.from_edition)}_state_available-"
                    f"{'_'.join(upgrade.state_available)}_state_on_success-{upgrade.state_on_success}"
                )
            else:
                action_name = f"{prototype.name}_{prototype.version}_{prototype.edition}_upgrade_{upgrade_name}"

            action_name = re.sub(r"\s+", "_", action_name).strip().lower()
            action_name = re.sub(r"\(|\)", "", action_name)
            source["action_name"] = action_name

            return [(cls._make(source=source, prototype=prototype), source)]

        actions = []
        for action_name, action_source in sorted(source.get("actions", {}).items(), key=lambda i: i[0]):
            action_source["action_name"] = action_name
            actions.append((cls._make(source=action_source, prototype=prototype), action_source))

        return actions

    @classmethod
    def _make(cls, source: dict, prototype: PrototypeData) -> "ActionData":
        # pylint: disable=too-many-branches,too-many-statements
        action_name = source["action_name"]
        validate_name(action_name, f"Action name \"{action_name}\" of {prototype.ref}")

        action_data = ActionData(prototype_ref=prototype.ref, name=action_name, type=source["type"])

        if action_data.type == "job":
            action_data.script = source["script"]
            action_data.script_type = source["script_type"]

        action_data.display_name = cls._get_display_name(source=source, prototype=prototype)

        value, legit = cls._dict_get(source=source, key="description")
        if legit:
            action_data.description = value
        value, legit = cls._dict_get(source=source, key="allow_to_terminate")
        if legit:
            action_data.allow_to_terminate = value
        value, legit = cls._dict_get(source=source, key="partial_execution")
        if legit:
            action_data.partial_execution = value
        value, legit = cls._dict_get(source=source, key="host_action")
        if legit:
            action_data.host_action = value
        value, legit = cls._dict_get(source=source, key="ui_options")
        if legit:
            action_data.ui_options = value
        value, legit = cls._dict_get(source=source, key="params")
        if legit:
            action_data.params = value
        value, legit = cls._dict_get(source=source, key="log_files")
        if legit:
            action_data.log_files = value
        value, legit = cls._dict_get(source=source, key="venv")
        if legit:
            action_data.venv = value
        value, legit = cls._dict_get(source=source, key="allow_in_maintenance_mode")
        if legit:
            action_data.allow_in_maintenance_mode = value
        _, legit = cls._dict_get(source=source, key="hc_acl")
        if legit:
            action_data.hostcomponentmap = cls._get_fixed_action_hc_acl(source=source, prototype=prototype)

        if MASKING in source:
            if STATES in source:
                raise AdcmEx(
                    "INVALID_OBJECT_DEFINITION",
                    f"Action {action_name} uses both mutual excluding states \"states\" and \"masking\"",
                )
            action_data.state_available = _deep_get(source, MASKING, STATE, AVAILABLE, default=ANY)
            action_data.state_unavailable = _deep_get(source, MASKING, STATE, UNAVAILABLE, default=[])
            action_data.state_on_success = _deep_get(source, ON_SUCCESS, STATE, default="")
            action_data.state_on_fail = _deep_get(source, ON_FAIL, STATE, default="")

            action_data.multi_state_available = _deep_get(source, MASKING, MULTI_STATE, AVAILABLE, default=ANY)
            action_data.multi_state_unavailable = _deep_get(source, MASKING, MULTI_STATE, UNAVAILABLE, default=[])
            action_data.multi_state_on_success_set = _deep_get(source, ON_SUCCESS, MULTI_STATE, SET, default=[])
            action_data.multi_state_on_success_unset = _deep_get(source, ON_SUCCESS, MULTI_STATE, UNSET, default=[])
            action_data.multi_state_on_fail_set = _deep_get(source, ON_FAIL, MULTI_STATE, SET, default=[])
            action_data.multi_state_on_fail_unset = _deep_get(source, ON_FAIL, MULTI_STATE, UNSET, default=[])
        else:
            if ON_SUCCESS in source or ON_FAIL in source:
                raise AdcmEx(
                    "INVALID_OBJECT_DEFINITION",
                    f"Action {action_name} uses \"on_success/on_fail\" states without \"masking\"",
                )
            action_data.state_available = _deep_get(source, STATES, AVAILABLE, default=[])
            action_data.state_unavailable = []
            action_data.state_on_success = _deep_get(source, STATES, ON_SUCCESS, default="")
            action_data.state_on_fail = _deep_get(source, STATES, ON_FAIL, default="")

            action_data.multi_state_available = ANY
            action_data.multi_state_unavailable = []
            action_data.multi_state_on_success_set = []
            action_data.multi_state_on_success_unset = []
            action_data.multi_state_on_fail_set = []
            action_data.multi_state_on_fail_unset = []

        return action_data

    @staticmethod
    def _get_fixed_action_hc_acl(source: dict, prototype: PrototypeData) -> list[dict]:
        hostcomponentmap = deepcopy(source.get("hc_acl", []))

        for idx, item in enumerate(hostcomponentmap):
            if "service" not in item:
                if prototype.type == "service":
                    item["service"] = prototype.name
                    hostcomponentmap[idx]["service"] = prototype.name

        return hostcomponentmap


class SubActionData(BaseData):
    # action: ActionData
    action_ref: str  # TODO: questionable

    name: str
    display_name: str = ""
    script: str
    script_type: str
    state_on_fail: str = ""
    multi_state_on_fail_set: Json[list] = []
    multi_state_on_fail_unset: Json[list] = []
    params: Json[dict] = {}
    allow_to_terminate: bool | None = None

    @classmethod
    def make_bulk(cls, action_data: ActionData, action_source: dict) -> list["SubActionData"]:
        if action_data.type != "task":
            return []

        sub_actions = []
        for sub in action_source["scripts"]:
            sub_actions.append(cls._make(action_data=action_data, sub_action_source=sub))

        return sub_actions

    @classmethod
    def _make(cls, action_data: ActionData, sub_action_source: dict) -> "SubActionData":
        subaction_data = cls(
            action_ref=action_data.ref,
            name=sub_action_source["name"],
            script=sub_action_source["script"],
            script_type=sub_action_source["script_type"],
        )

        subaction_data.display_name = sub_action_source["name"]
        if "display_name" in sub_action_source:
            subaction_data.display_name = sub_action_source["display_name"]

        value, legit = cls._dict_get(source=sub_action_source, key="params")
        if legit:
            subaction_data.params = value
        value, legit = cls._dict_get(source=sub_action_source, key="allow_to_terminate")
        if legit:
            subaction_data.allow_to_terminate = value

        on_fail = sub_action_source.get(ON_FAIL, "")
        if isinstance(on_fail, str):
            subaction_data.state_on_fail = on_fail
            subaction_data.multi_state_on_fail_set = []
            subaction_data.multi_state_on_fail_unset = []
        elif isinstance(on_fail, dict):
            subaction_data.state_on_fail = _deep_get(on_fail, STATE, default="")
            subaction_data.multi_state_on_fail_set = _deep_get(on_fail, MULTI_STATE, SET, default=[])
            subaction_data.multi_state_on_fail_unset = _deep_get(on_fail, MULTI_STATE, UNSET, default=[])

        return subaction_data


class UpgradeData(BaseData):
    name: str = ""
    description: str = ""
    min_version: str
    max_version: str
    min_strict: bool = False
    max_strict: bool = False
    from_edition: Json[list[str]] = DEFAULT_FROM_EDITION
    state_available: Json[list] = []
    state_on_success: str = ""
    # action: Optional["ActionData"] = None
    action_ref: str = ""  # TODO: questionable

    @property
    def ref(self):
        return f"Upgrade \"{self.name}\" of action \"{self.action_ref}\""

    @classmethod
    def make_bulk(cls, prototype: PrototypeData, source: dict) -> list[tuple["UpgradeData", dict]]:
        upgrades = []
        for item in source.get("upgrade", []):
            upgrades.append(cls._make(prototype=prototype, source=item))

        return upgrades

    @classmethod
    def _make(cls, prototype: PrototypeData, source: dict) -> tuple["UpgradeData", dict]:
        # pylint: disable=too-many-branches
        source = deepcopy(source)

        check_upgrade(prototype, source)

        if "min" in source["versions"]:
            min_version = source["versions"]["min"]
            min_strict = False
        elif "min_strict" in source["versions"]:
            min_version = source["versions"]["min_strict"]
            min_strict = True
        else:
            raise RuntimeError("no min/min_strict version defined")

        if "max" in source["versions"]:
            max_version = source["versions"]["max"]
            max_strict = False
        elif "max_strict" in source["versions"]:
            max_version = source["versions"]["max_strict"]
            max_strict = True
        else:
            raise RuntimeError("no max/max_strict version defined")

        upgrade = UpgradeData(
            name=source["name"],
            min_version=min_version,
            min_strict=min_strict,
            max_version=max_version,
            max_strict=max_strict,
        )

        value, legit = cls._dict_get(source=source, key="description")
        if legit:
            upgrade.description = value

        states = source.get("states", None)
        if states is not None:
            value, legit = cls._dict_get(source=states, key="available")
            if legit:
                upgrade.state_available = value
            value, legit = cls._dict_get(source=states, key="on_success")
            if legit:
                upgrade.state_on_success = value

        value, legit = cls._dict_get(source=source, key="from_edition")
        if legit:
            upgrade.from_edition = value

        return upgrade, source


class BundleDefinition:
    """
    Class for saving whole bundle definition in python's structures
    to perform validations and save bundle to DB
    """

    def __init__(self):
        self._definitions = []
        self._validate_funcs = (self._validate_actions, self._validate_components, self._validate_config)

    def add_definition(self, definition_file: DefinitionFile) -> None:
        """Split objects' definitions into python objects"""
        definition_data = DefinitionData(definition_file=definition_file)
        obj_list = {}

        if isinstance(definition_file.config, dict):
            check_object_definition(
                definition_file.filename, definition_file.config, definition_file.config["type"], obj_list
            )
            self._make_objects(config=definition_file.config, definition_data=definition_data)

        elif isinstance(definition_file.config, list):
            for obj_def in definition_file.config:
                check_object_definition(definition_file.filename, obj_def, obj_def["type"], obj_list)
                self._make_objects(config=obj_def, definition_data=definition_data)

        else:
            raise NotImplementedError

        self._definitions.append(definition_data)

    @staticmethod
    def _make_objects(config: dict, definition_data: DefinitionData) -> None:
        prototype = PrototypeData.make(source=config, definition_data=definition_data)
        definition_data.prototypes.append(prototype)

        for action_data, action_source in ActionData.make_bulk(source=config, prototype=prototype):
            definition_data.actions.append(action_data)
            for sub_action in SubActionData.make_bulk(action_data=action_data, action_source=action_source):
                definition_data.sub_actions.append(sub_action)

        for upgrade, upgrade_source in UpgradeData.make_bulk(prototype=prototype, source=config):
            definition_data.upgrades.append(upgrade)

            # TODO: проверить на апгейдах с ["scripts"], когда upgrade.action != None
            upgrade_action_data = None
            upgrade_action_source = None
            if "scripts" in upgrade_source:
                actions = ActionData.make_bulk(source=upgrade_source, prototype=prototype, upgrade=upgrade)
                if len(actions) != 1:
                    raise RuntimeError("Not one action for upgrade")
                upgrade_action_data, upgrade_action_source = actions[0]
                upgrade.action_ref = upgrade_action_data.ref

            if upgrade_action_data is not None:
                definition_data.actions.append(upgrade_action_data)
                for sub_action in SubActionData.make_bulk(
                    action_data=upgrade_action_data, action_source=upgrade_action_source
                ):
                    definition_data.sub_actions.append(sub_action)

        # TODO: save_prototype_config after each prototype, action, component
        # TODO: save_components
        # TODO: save_export
        # TODO: save_import

    def save_to_db(self) -> None:
        pass

    def validate(self):
        # TODO: remove dev code
        # from pprint import pformat
        # logger.critical(f"DEBUG_BUNDLE_DEF\n{pformat(self._definitions)}")
        self._validate()

    def _validate_actions(self):
        pass

    def _validate_components(self):
        pass

    def _validate_config(self):
        pass

    def _validate(self):
        for validate_func in self._validate_funcs:
            validate_func()
