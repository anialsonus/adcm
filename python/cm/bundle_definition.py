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
from dataclasses import dataclass, field
from datetime import datetime as dt
from pathlib import Path
from typing import List

from django.conf import settings

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
    validate_name,
)

# pylint: disable=too-many-instance-attributes


@dataclass
class Definition:
    """Definition from .yaml file"""

    path: str
    fname: str
    conf: dict
    adcm_: bool = False
    obj_list: dict = field(default_factory=dict)


@dataclass
class DefinitionData:
    """Definition divided into entities (lists od dataclasses)"""

    prototypes: list = field(default_factory=list)
    actions: list = field(default_factory=list)
    sub_actions: list = field(default_factory=list)
    prototype_configs: list = field(default_factory=list)
    upgrades: list = field(default_factory=list)
    prototype_exports: list = field(default_factory=list)
    prototype_imports: list = field(default_factory=list)


@dataclass
class BundleData:
    name: str
    version: str
    hash: str
    version_order: int = 0
    edition: str = "community"
    description: str = ""
    date: str = str(dt.utcnow())
    category: int | None = None


@dataclass
class PrototypeData:
    type: str
    name: str
    version: str
    parent = None  # TODO: type None | self (typing.Self)
    bundle: BundleData | None = None
    path: str = ""
    license: str = "absent"
    license_path: str | None = None
    license_hash: str | None = None
    display_name: str = ""
    version_order: int = 0
    required: bool = False
    shared: bool = False
    constraint: str = '[0, "+"]'
    requires: str = "[]"
    bound_to: str = "{}"
    adcm_min_version: str | None = None
    monitoring: str = "active"
    description: str = ""
    config_group_customization: bool = False
    venv: str = "default"
    allow_maintenance_mode: bool = False
    edition: str = "community"

    @property
    def ref(self):
        return f"{self.type} \"{self.name}\" {self.version}"


@dataclass
class ActionData:
    prototype: PrototypeData
    name: str
    type: str
    script: str | None = None
    script_type: str | None = None
    display_name: str = ""
    description: str = ""
    ui_options: str = "{}"
    state_available: str = "[]"
    state_unavailable: str = "[]"
    state_on_success: str = ""
    state_on_fail: str = ""
    multi_state_available: str = "any"
    multi_state_unavailable: str = "[]"
    multi_state_on_success_set: str = "[]"
    multi_state_on_success_unset: str = "[]"
    multi_state_on_fail_set: str = "[]"
    multi_state_on_fail_unset: str = "[]"
    params: str = "{}"
    log_files: str = "[]"
    hostcomponentmap: str = "[]"
    allow_to_terminate: bool = False
    partial_execution: bool = False
    host_action: bool = False
    allow_in_maintenance_mode: bool = False
    venv: str = "default"


@dataclass
class SubActionData:
    action: ActionData
    name: str
    script: str
    script_type: str
    display_name: str = ""
    state_on_fail: str = ""
    multi_state_on_fail_set: str = "[]"
    multi_state_on_fail_unset: str = "[]"
    params: str = "{}"
    allow_to_terminate: bool | None = None


@dataclass
class UpgradeData:
    min_version: str
    max_version: str
    name: str = ""
    description: str = ""
    min_strict: bool = False
    max_strict: bool = False
    from_edition: str = "[\"community\"]"
    state_available: str = "[]"
    state_on_success: str = ""
    action: ActionData | None = None


class BundleDefinition:
    """
    Class for saving whole bundle definition in python's structures
    to perform validations and save bundle to db if validations was successful
    """

    def __init__(self, bundle_hash: str):
        self._bundle_hash = bundle_hash

        # analog of second_pass() on `stage` tables TODO: перенести сюда
        self._validate_funcs = (self._validate_actions, self._validate_components, self._validate_config)

        # analogue of `stage` tables
        self._definitions = []
        # self.prototypes = []
        # self.actions = []
        # self.prototype_configs = []
        # self.upgrades = []
        # self.prototype_exports = []
        # self.prototype_imports = []

    def add_definition(self, definition: Definition) -> None:
        """split objects' definitions into prototypes"""

        if isinstance(definition.conf, dict):
            check_object_definition(definition.fname, definition.conf, definition.conf["type"], definition.obj_list)
            self._add_prototype(definition.conf, definition)

        elif isinstance(definition.conf, list):
            for obj_def in definition.conf:
                check_object_definition(definition.fname, obj_def, obj_def["type"], definition.obj_list)
                self._add_prototype(obj_def, definition)

        else:
            raise NotImplementedError

    def save(self) -> None:
        # TODO: link all to BundleData
        self._save_to_db()

    def validate(self):
        self._validate()

    def _validate(self):
        # TODO: rework commented
        # if not any(
        #     (
        #         self.prototypes,
        #         self.actions,
        #         self.prototype_configs,
        #         self.upgrades,
        #         self.prototype_exports,
        #         self.prototype_imports,
        #     )
        # ):
        #     raise RuntimeError("Add some definitions via `add_definition()` first")

        for validate_func in self._validate_funcs:
            validate_func()

    def _save_to_db(self):
        pass

    def _validate_actions(self):
        pass

    def _validate_components(self):
        pass

    def _validate_config(self):
        pass

    # TODO: validate whole definition. new containers for not validated yet???
    def _add_prototype(self, conf: dict, definition: Definition) -> None:
        # proto_index = len(self.prototypes)
        definition_data = DefinitionData()

        prototype = PrototypeData(name=conf["name"], type=conf["type"], path=definition.path, version=conf["version"])

        if conf.get("required") is not None:
            prototype.required = conf["required"]
        if conf.get("shared") is not None:
            prototype.shared = conf["shared"]
        if conf.get("monitoring") is not None:
            prototype.monitoring = conf["monitoring"]
        if conf.get("description") is not None:
            prototype.description = conf["description"]
        if conf.get("adcm_min_version") is not None:
            prototype.adcm_min_version = conf["adcm_min_version"]
        if conf.get("venv") is not None:
            prototype.venv = conf["venv"]
        if conf.get("edition") is not None:
            prototype.edition = conf["edition"]
        if conf.get("allow_maintenance_mode") is not None:
            prototype.allow_maintenance_mode = conf["allow_maintenance_mode"]

        prototype.display_name = self._get_display_name(conf, prototype)
        prototype.config_group_customization = self._get_config_group_customization(
            conf=conf, proto=prototype, definition_data=definition_data
        )

        if license_hash := self._get_license_hash(conf, prototype, definition) != "absent" and prototype.type not in [
            "cluster",
            "service",
            "provider",
        ]:
            raise AdcmEx(
                "INVALID_OBJECT_DEFINITION",
                f"Invalid license definition in {prototype.ref}. License can be placed in cluster, service or provider",
            )
        if conf.get("license") and license_hash != "absent":
            prototype.license_path = conf["license"]
            prototype.license_hash = license_hash

        definition_data.prototypes.append(prototype)
        self._save_actions(definition_data=definition_data, prototype=prototype, config=conf, upgrade=None)  # TODO

        # TODO: save_actions
        # TODO: save_upgrade
        # TODO: save_components
        # TODO: save_prototype_config
        # TODO: save_export
        # TODO: save_import

        self._definitions.append(definition_data)

    @staticmethod
    def _get_display_name(conf: dict, prototype: PrototypeData) -> str:
        if "display_name" in conf:
            return conf["display_name"]

        return prototype.name

    def _get_license_hash(self, conf: dict, prototype: PrototypeData, definition: Definition) -> str:
        if "license" not in conf:
            return "absent"

        else:
            if conf["license"][0:2] == "./":
                path = Path(settings.BUNDLE_DIR, self._bundle_hash, prototype.path, conf["license"])
            else:
                path = Path(settings.BUNDLE_DIR, self._bundle_hash, definition.fname)

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

    def _get_config_group_customization(
        self, conf: dict, proto: PrototypeData, definition_data: DefinitionData
    ) -> bool:
        if not conf:
            return False

        if "config_group_customization" not in conf:
            service_proto = None

            if proto.type == "service":
                service_proto = [i for i in definition_data.prototypes + [proto] if i.type == "cluster"]
                if len(service_proto) < 1:
                    logger.debug("Can't find cluster for service %s", proto)
                elif len(service_proto) > 1:
                    logger.debug("Found more than one cluster for service %s", proto)
                else:
                    service_proto = service_proto[0]

            elif proto.type == "component":
                service_proto = proto.parent

            if service_proto:
                return service_proto.config_group_customization

        return False

    def _save_actions(
        self,
        definition_data: DefinitionData,
        prototype: PrototypeData,
        config: dict,
        upgrade: UpgradeData | None = None,
    ):
        config_ = deepcopy(config)

        if config_.get("versions") is not None:
            config_["type"] = "task"
            upgrade_name = config_["name"]
            config_["display_name"] = f"Upgrade: {upgrade_name}"

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

            self._make_action(
                prototype=prototype, action=config_, action_name=action_name, definition_data=definition_data
            )

        if config_.get("actions") is None:
            return None

        for action_name in sorted(config_["actions"]):
            self._make_action(
                prototype=prototype,
                action=config_["actions"][action_name],
                action_name=action_name,
                definition_data=definition_data,
            )

        return None

    def _make_action(
        self, prototype: PrototypeData, action: dict, action_name: str, definition_data: DefinitionData
    ) -> None:
        # pylint: disable=too-many-branches,too-many-statements
        validate_name(action_name, f"Action name \"{action_name}\" of {prototype.ref}")
        action_data = ActionData(prototype=prototype, name=action_name, type=action["type"])

        if action_data.type == "job":
            action.script = action["script"]
            action.script_type = action["script_type"]

        action_data.display_name = self._get_display_name(conf=action, prototype=prototype)

        if action.get("description") is not None:
            action_data.description = action["description"]
        if action.get("allow_to_terminate") is not None:
            action_data.allow_to_terminate = action["allow_to_terminate"]
        if action.get("partial_execution") is not None:
            action_data.partial_execution = action["partial_execution"]
        if action.get("host_action") is not None:
            action_data.host_action = action["host_action"]
        if action.get("ui_options") is not None:
            action_data.ui_options = action["ui_options"]
        if action.get("params") is not None:
            action_data.params = action["params"]
        if action.get("log_files") is not None:
            action_data.log_files = action["log_files"]
        if action.get("venv") is not None:
            action_data.venv = action["venv"]
        if action.get("allow_in_maintenance_mode") is not None:
            action_data.allow_in_maintenance_mode = action["allow_in_maintenance_mode"]
        if action.get("hc_acl") is not None:
            action_data.hostcomponentmap = self._get_fixed_action_hc_acl(prototype=prototype, action=action)

        if MASKING in action:
            if STATES in action:
                raise AdcmEx(
                    "INVALID_OBJECT_DEFINITION",
                    f"Action {action_name} uses both mutual excluding states \"states\" and \"masking\"",
                )
            action_data.state_available = _deep_get(action, MASKING, STATE, AVAILABLE, default=ANY)
            action_data.state_unavailable = _deep_get(action, MASKING, STATE, UNAVAILABLE, default=[])
            action_data.state_on_success = _deep_get(action, ON_SUCCESS, STATE, default="")
            action_data.state_on_fail = _deep_get(action, ON_FAIL, STATE, default="")

            action_data.multi_state_available = _deep_get(action, MASKING, MULTI_STATE, AVAILABLE, default=ANY)
            action_data.multi_state_unavailable = _deep_get(action, MASKING, MULTI_STATE, UNAVAILABLE, default=[])
            action_data.multi_state_on_success_set = _deep_get(action, ON_SUCCESS, MULTI_STATE, SET, default=[])
            action_data.multi_state_on_success_unset = _deep_get(action, ON_SUCCESS, MULTI_STATE, UNSET, default=[])
            action_data.multi_state_on_fail_set = _deep_get(action, ON_FAIL, MULTI_STATE, SET, default=[])
            action_data.multi_state_on_fail_unset = _deep_get(action, ON_FAIL, MULTI_STATE, UNSET, default=[])
        else:
            if ON_SUCCESS in action or ON_FAIL in action:
                raise AdcmEx(
                    "INVALID_OBJECT_DEFINITION",
                    f"Action {action_name} uses \"on_success/on_fail\" states without \"masking\"",
                )
            action_data.state_available = _deep_get(action, STATES, AVAILABLE, default=[])
            action_data.state_unavailable = []
            action_data.state_on_success = _deep_get(action, STATES, ON_SUCCESS, default="")
            action_data.state_on_fail = _deep_get(action, STATES, ON_FAIL, default="")

            action_data.multi_state_available = ANY
            action_data.multi_state_unavailable = []
            action_data.multi_state_on_success_set = []
            action_data.multi_state_on_success_unset = []
            action_data.multi_state_on_fail_set = []
            action_data.multi_state_on_fail_unset = []

        self._make_sub_actions(action=action, action_data=action_data, definition_data=definition_data)
        # TODO: cm.stack.save_prototype_config

        definition_data.actions.append(action_data)

    @staticmethod
    def _get_fixed_action_hc_acl(prototype: PrototypeData, action: dict) -> List[dict]:
        hostcomponentmap = deepcopy(action.get("hc_acl", []))

        for idx, item in enumerate(hostcomponentmap):
            if "service" not in item:
                if prototype.type == "service":
                    item["service"] = prototype.name
                    action["hc_acl"][idx]["service"] = prototype.name

        return hostcomponentmap

    def _make_sub_actions(self, action: dict, action_data: ActionData, definition_data: DefinitionData):
        if action_data.type != "task":
            return

        for sub in action["scripts"]:
            subaction_data = SubActionData(
                action=action_data, name=sub["name"], script=sub["script"], script_type=sub["script_type"]
            )

            subaction_data.display_name = sub["name"]
            if "display_name" in sub:
                subaction_data.display_name = sub["display_name"]
            if sub.get("params") is not None:
                subaction_data.params = sub["params"]
            if sub.get("allow_to_terminate") is not None:
                subaction_data.allow_to_terminate = sub["allow_to_terminate"]

            on_fail = sub.get(ON_FAIL, "")
            if isinstance(on_fail, str):
                subaction_data.state_on_fail = on_fail
                subaction_data.multi_state_on_fail_set = []
                subaction_data.multi_state_on_fail_unset = []
            elif isinstance(on_fail, dict):
                subaction_data.state_on_fail = _deep_get(on_fail, STATE, default="")
                subaction_data.multi_state_on_fail_set = _deep_get(on_fail, MULTI_STATE, SET, default=[])
                subaction_data.multi_state_on_fail_unset = _deep_get(on_fail, MULTI_STATE, UNSET, default=[])

            definition_data.sub_actions.append(subaction_data)
