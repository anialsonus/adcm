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

from pathlib import Path
from typing import Any

from django.conf import settings
from yaml import safe_load

from cm.models import (
    Action,
    Cluster,
    Component,
    Host,
    PrototypeConfig,
    Service,
)
from cm.services.bundle import BundlePathResolver, detect_relative_path_to_bundle_root
from cm.services.cluster import retrieve_related_cluster_topology
from cm.services.config.patterns import Pattern
from cm.services.job.inventory import get_cluster_vars
from cm.services.job.jinja_scripts import get_action_info
from cm.services.template import TemplateBuilder

_TEMPLATE_CONFIG_DELETE_FIELDS = {"yspec", "option", "activatable", "active", "read_only", "writable", "subs", "source"}


def get_jinja_config(
    action: Action, cluster_relative_object: Cluster | Service | Component | Host
) -> tuple[list[PrototypeConfig], dict[str, Any]]:
    resolver = BundlePathResolver(bundle_hash=action.prototype.bundle.hash)
    jinja_conf_file = resolver.resolve(action.config_jinja)

    template_builder = TemplateBuilder(
        template_path=jinja_conf_file,
        context={
            **get_cluster_vars(topology=retrieve_related_cluster_topology(orm_object=cluster_relative_object)).dict(
                by_alias=True, exclude_defaults=True
            ),
            "action": get_action_info(action=action),
        },
    )

    configs = []
    attr = {}
    for config in template_builder.data:
        for normalized_config in _normalize_config(
            config=config, dir_with_config=jinja_conf_file.parent.relative_to(resolver.bundle_root), resolver=resolver
        ):
            configs.append(PrototypeConfig(prototype=action.prototype, action=action, **normalized_config))

            if (
                normalized_config["type"] == "group"
                and "activatable" in normalized_config["limits"]
                and "active" in normalized_config["limits"]
                and normalized_config.get("name")
            ):
                attr[normalized_config["name"]] = normalized_config["limits"]

    return configs, attr


def _normalize_config(
    config: dict, dir_with_config: Path, resolver: BundlePathResolver, name: str = "", subname: str = ""
) -> list[dict]:
    """`dir_with_config` should be relative to bundle root"""
    config_list = [config]

    name = name or config["name"]
    config["name"] = name
    if subname:
        config["subname"] = subname

    if config.get("display_name") is None:
        config["display_name"] = subname or name

    config["limits"] = _get_limits(config=config, dir_with_config=dir_with_config, resolver=resolver)

    if config["type"] in settings.STACK_FILE_FIELD_TYPES and config.get("default"):
        config["default"] = detect_relative_path_to_bundle_root(
            source_file_dir=dir_with_config, raw_path=config["default"]
        )

    if "subs" in config:
        for subconf in config["subs"]:
            config_list.extend(
                _normalize_config(
                    config=subconf,
                    dir_with_config=dir_with_config,
                    resolver=resolver,
                    name=name,
                    subname=subconf["name"],
                ),
            )

    for field in _TEMPLATE_CONFIG_DELETE_FIELDS:
        if field in config:
            del config[field]

    return config_list


def _get_limits(config: dict, dir_with_config: Path, resolver: BundlePathResolver) -> dict:
    limits = {}

    if "pattern" in config:
        if config["type"] not in ("string", "text", "password", "secrettext"):
            message = f"Incorrectly rendered `config_jinja` file. `pattern` is not allowed in {config['type']}"
            raise RuntimeError(message)

        pattern = Pattern(regex_pattern=config.pop("pattern"))
        if not pattern.is_valid:
            display_name = config.get("display_name", config["name"])
            message = f"The pattern attribute value of {display_name} config parameter is not valid regular expression"
            raise RuntimeError(message)

        default = config.get("default")
        if default is not None and not pattern.matches(str(default)):
            display_name = config.get("display_name", config["name"])
            message = f"Default attribute value of {display_name} config parameter does not match pattern"
            raise RuntimeError(message)

        limits["pattern"] = pattern.raw

    if "yspec" in config and config["type"] in settings.STACK_COMPLEX_FIELD_TYPES:
        spec_path = detect_relative_path_to_bundle_root(source_file_dir=dir_with_config, raw_path=config["yspec"])
        limits["yspec"] = safe_load(stream=resolver.resolve(spec_path).read_text(encoding="utf-8"))

    if "option" in config and config["type"] == "option":
        limits["option"] = config["option"]

    if "source" in config and config["type"] == "variant":
        variant_type = config["source"]["type"]
        source = {"type": variant_type, "args": None}

        source["strict"] = config["source"].get("strict", True)

        if variant_type == "inline":
            source["value"] = config["source"]["value"]
        elif variant_type in ("config", "builtin"):
            source["name"] = config["source"]["name"]

        if variant_type == "builtin" and "args" in config["source"]:
            source["args"] = config["source"]["args"]

        limits["source"] = source

    if "activatable" in config and config["type"] == "group":
        limits.update(
            activatable=config["activatable"],
            active=False,
        )

        if "active" in config:
            limits.update(active=config["active"])

    if config["type"] in settings.STACK_NUMERIC_FIELD_TYPES:
        if "min" in config:
            limits["min"] = config["min"]

        if "max" in config:
            limits["max"] = config["max"]

    for label in ("read_only", "writable"):
        if label in config:
            limits[label] = config[label]

    return limits
