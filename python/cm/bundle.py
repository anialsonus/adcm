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

import functools
import hashlib
import shutil
import tarfile
from dataclasses import dataclass, field
from datetime import datetime as dt
from pathlib import Path
from typing import List

from django.conf import settings
from django.db import IntegrityError, transaction
from version_utils import rpm

import cm.stack
import cm.status_api
from cm.adcm_config import init_object_config, proto_ref, switch_config
from cm.errors import AdcmEx
from cm.errors import raise_adcm_ex as err
from cm.logger import logger
from cm.models import (
    ADCM,
    Action,
    Bundle,
    Cluster,
    HostProvider,
    ProductCategory,
    Prototype,
    PrototypeConfig,
    PrototypeExport,
    PrototypeImport,
    StageAction,
    StagePrototype,
    StagePrototypeConfig,
    StagePrototypeExport,
    StagePrototypeImport,
    StageSubAction,
    StageUpgrade,
    SubAction,
    Upgrade,
)
from rbac.models import Role
from rbac.upgrade.role import prepare_action_roles

# pylint: disable=too-many-instance-attributes, too-many-lines


@dataclass
class Definition:
    path: str
    fname: str
    conf: dict
    adcm_: bool = False
    obj_list: dict = field(default_factory=dict)


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


class BundleDefinition:
    """
    Class for saving whole bundle definition in python's structures
    to perform validations and save bundle to db if validations was successful
    """

    def __init__(self, bundle_hash: str):
        self._bundle_hash = bundle_hash

        # analog of second_pass() on `stage` tables TODO: перенести сюда
        self._validate_funcs = (self._validate_actions, self._validate_components, self._validate_config)

        # analogues of `stage` tables
        self.prototypes = []
        self.actions = []
        self.prototype_configs = []
        self.upgrades = []
        self.prototype_exports = []
        self.prototype_imports = []

    def add_definition(self, definition: Definition) -> None:
        """split objects' definitions into prototypes"""
        if isinstance(definition.conf, dict):
            cm.stack.check_object_definition(
                definition.fname, definition.conf, definition.conf["type"], definition.obj_list
            )
            self._add_prototype(definition.conf, definition)

        elif isinstance(definition.conf, list):
            for obj_def in definition.conf:
                cm.stack.check_object_definition(definition.fname, obj_def, obj_def["type"], definition.obj_list)
                self._add_prototype(obj_def, definition)

        else:
            raise NotImplementedError

    def save(self) -> None:
        # TODO: link all to Bundle
        self._validate()
        self._save_to_db()

    def _validate(self):
        if not any(
            (
                self.prototypes,
                self.actions,
                self.prototype_configs,
                self.upgrades,
                self.prototype_exports,
                self.prototype_imports,
            )
        ):
            raise RuntimeError("Add some definitions via `add_definition()` first")

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

    def _add_prototype(self, conf: dict, definition: Definition) -> None:
        # proto_index = len(self.prototypes)
        prototype = PrototypeData(name=conf["name"], type=conf["type"], path=definition.path, version=conf["version"])

        if conf.get("required"):
            prototype.required = conf["required"]
        if conf.get("shared"):
            prototype.shared = conf["shared"]
        if conf.get("monitoring"):
            prototype.monitoring = conf["monitoring"]
        if conf.get("description"):
            prototype.description = conf["description"]
        if conf.get("adcm_min_version"):
            prototype.adcm_min_version = conf["adcm_min_version"]
        if conf.get("venv"):
            prototype.venv = conf["venv"]
        if conf.get("edition"):
            prototype.edition = conf["edition"]
        if conf.get("allow_maintenance_mode"):
            prototype.allow_maintenance_mode = conf["allow_maintenance_mode"]

        prototype.display_name = self._get_display_name(conf, prototype)
        prototype.config_group_customization = self._get_config_group_customization(conf, prototype)
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

        self.prototypes.append(prototype)

        # TODO: save_actions
        # TODO: save_upgrade
        # TODO: save_components
        # TODO: save_prototype_config
        # TODO: save_export
        # TODO: save_import

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
            except PermissionError:
                raise AdcmEx("CONFIG_TYPE_ERROR", f'"license file" "{path}" can not be open ({prototype.ref})') from e

            if license_file is not None:
                body = license_file.read()
                license_file.close()

                sha1 = hashlib.sha256()
                sha1.update(body.encode(settings.ENCODING_UTF_8))

                return sha1.hexdigest()

        return "absent"

    def _get_config_group_customization(self, conf: dict, proto: PrototypeData) -> bool:
        if "config_group_customization" not in conf:
            service_proto = None

            if proto.type == "service":
                service_proto = [i for i in self.prototypes + [proto] if i.type == "cluster"]
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

    # cm.stack.save_actions  TODO: апгрейды, versions, etc
    def _fix_actions(self, upgrade: dict | None = None):
        pass


STAGE = (  # TODO: remove
    StagePrototype,
    StageAction,
    StagePrototypeConfig,
    StageUpgrade,
    StagePrototypeExport,
    StagePrototypeImport,
)


def load_bundle(bundle_file) -> Bundle:
    logger.info('loading bundle file "%s" ...', bundle_file)

    check_stage()  # TODO: remove

    bundle_path = str(settings.DOWNLOAD_DIR / bundle_file)
    bundle_hash = get_hash_safe(path=bundle_path)
    path = untar_safe(bundle_hash=bundle_hash, path=bundle_path)

    try:
        bundle_def = BundleDefinition(bundle_hash=bundle_hash)

        definitions = get_bundle_definitions(path=path, bundle_hash=bundle_hash)  # ???
        if not definitions:
            raise AdcmEx("BUNDLE_ERROR", f"Can't find any definitions in bundle {bundle_file}")

        for definition in definitions:
            bundle_def.add_definition(definition)
            # cm.stack.save_definition_to_stage(bundle_hash=bundle_hash, **definition.__dict__)

        bundle_def.save()

        process_bundle(path, bundle_hash)  # TODO: remove
        bundle_proto = get_stage_bundle(bundle_file)  # TODO: remove
        second_pass()  # TODO: move checks to BundleDefinition._validate, remove
    except Exception as e:
        clear_stage()  # TODO: remove
        shutil.rmtree(path)
        raise e

    try:
        bundle = copy_stage(bundle_hash, bundle_proto)
        order_versions()
        clear_stage()
        ProductCategory.re_collect()
        bundle.refresh_from_db()
        prepare_action_roles(bundle)
        cm.status_api.post_event("create", "bundle", bundle.id)
        return bundle
    except:
        clear_stage()
        raise


def update_bundle(bundle):
    try:
        check_stage()
        process_bundle(settings.BUNDLE_DIR / bundle.hash, bundle.hash)
        get_stage_bundle(bundle.name)
        second_pass()
        update_bundle_from_stage(bundle)
        order_versions()
        clear_stage()
    except:
        clear_stage()
        raise


def order_model_versions(model):
    items = []
    for obj in model.objects.all():
        items.append(obj)
    ver = ""
    count = 0
    for obj in sorted(
        items,
        key=functools.cmp_to_key(lambda obj1, obj2: rpm.compare_versions(obj1.version, obj2.version)),
    ):
        if ver != obj.version:
            count += 1
        obj.version_order = count
        ver = obj.version
    # Update all table in one time. That is much faster than one by one method
    model.objects.bulk_update(items, ["version_order"])


def order_versions():
    order_model_versions(Prototype)
    order_model_versions(Bundle)


def untar_safe(bundle_hash, path) -> str:
    try:
        dir_path = untar(bundle_hash, path)
    except tarfile.ReadError:
        err("BUNDLE_ERROR", f"Can't open bundle tar file: {path}")
    return dir_path


def untar(bundle_hash: str, bundle: str) -> str:
    path = settings.BUNDLE_DIR / bundle_hash
    if path.is_dir():
        try:
            existed = Bundle.objects.get(hash=bundle_hash)
            raise AdcmEx(
                "BUNDLE_ERROR",
                f"Bundle already exists. Name: {existed.name}, version: {existed.version}, edition: {existed.edition}",
            )
        except Bundle.DoesNotExist:
            logger.warning(
                (
                    "There is no bundle with hash %s in DB, "
                    "but there is a dir on disk with this hash. Dir will be rewrited."
                ),
                bundle_hash,
            )
    tar = tarfile.open(bundle)
    tar.extractall(path=path)
    tar.close()
    return path


def get_hash_safe(path: str) -> str:
    try:
        bundle_hash = get_hash(path)
    except FileNotFoundError:
        err("BUNDLE_ERROR", f"Can't find bundle file: {path}")
    except PermissionError:
        err("BUNDLE_ERROR", f"Can't open bundle file: {path}")
    return bundle_hash


def get_hash(bundle_file: str) -> str:
    sha1 = hashlib.sha1()
    with open(bundle_file, "rb") as fp:
        for data in iter(lambda: fp.read(settings.FILE_READ_CHUNK_SIZE), b""):
            sha1.update(data)
    return sha1.hexdigest()


def load_adcm():
    check_stage()
    adcm_file = settings.BASE_DIR / "conf" / "adcm" / "config.yaml"
    conf = cm.stack.read_definition(adcm_file, "yaml")
    if not conf:
        logger.warning("Empty adcm config (%s)", adcm_file)
        return
    try:
        cm.stack.save_definition_to_stage("", adcm_file, conf, {}, "adcm", True)
        process_adcm()
    except:
        clear_stage()
        raise
    clear_stage()


def process_adcm():
    adcm_stage_proto = StagePrototype.objects.get(type="adcm")
    adcm = ADCM.objects.filter()
    if adcm:
        old_proto = adcm[0].prototype
        new_proto = adcm_stage_proto
        if old_proto.version == new_proto.version:
            logger.debug("adcm vesrion %s, skip upgrade", old_proto.version)
        elif rpm.compare_versions(old_proto.version, new_proto.version) < 0:
            bundle = copy_stage("adcm", adcm_stage_proto)
            upgrade_adcm(adcm[0], bundle)
        else:
            msg = "Current adcm version {} is more than or equal to upgrade version {}"
            err("UPGRADE_ERROR", msg.format(old_proto.version, new_proto.version))
    else:
        bundle = copy_stage("adcm", adcm_stage_proto)
        init_adcm(bundle)


def init_adcm(bundle):
    proto = Prototype.objects.get(type="adcm", bundle=bundle)
    with transaction.atomic():
        adcm = ADCM.objects.create(prototype=proto, name="ADCM")
        obj_conf = init_object_config(proto, adcm)
        adcm.config = obj_conf
        adcm.save()
    logger.info("init adcm object version %s OK", proto.version)
    return adcm


def upgrade_adcm(adcm, bundle):
    old_proto = adcm.prototype
    new_proto = Prototype.objects.get(type="adcm", bundle=bundle)
    if rpm.compare_versions(old_proto.version, new_proto.version) >= 0:
        msg = "Current adcm version {} is more than or equal to upgrade version {}"
        err("UPGRADE_ERROR", msg.format(old_proto.version, new_proto.version))
    with transaction.atomic():
        adcm.prototype = new_proto
        adcm.save()
        switch_config(adcm, new_proto, old_proto)
    logger.info("upgrade adcm OK from version %s to %s", old_proto.version, adcm.prototype.version)
    return adcm


def get_bundle_definitions(path: str, bundle_hash: str) -> List[Definition]:
    definitions = []

    for conf_path, conf_file, conf_type in cm.stack.get_config_files(path=path, bundle_hash=bundle_hash):
        definition = cm.stack.read_definition(conf_file, conf_type)
        if definition:
            definitions.append(
                Definition(
                    path=conf_path,
                    fname=conf_file,
                    conf=definition,
                )
            )

    return definitions


def process_bundle(path, bundle_hash):
    obj_list = {}

    for conf_path, conf_file, conf_type in cm.stack.get_config_files(path, bundle_hash):
        conf = cm.stack.read_definition(conf_file, conf_type)
        if conf:
            cm.stack.save_definition_to_stage(conf_path, conf_file, conf, obj_list, bundle_hash)


def check_stage() -> None:
    for model in STAGE:
        if model.objects.all().count():
            raise AdcmEx("BUNDLE_ERROR", f"Stage is not empty {model}")


def copy_obj(orig, clone, fields):
    obj = clone()
    for f in fields:
        setattr(obj, f, getattr(orig, f))
    return obj


def update_obj(dest, source, fields):
    for f in fields:
        setattr(dest, f, getattr(source, f))


def re_check_actions():
    for act in StageAction.objects.all():
        if not act.hostcomponentmap:
            continue
        hc = act.hostcomponentmap
        ref = f'in hc_acl of action "{act.name}" of {proto_ref(act.prototype)}'
        for item in hc:
            stage_proto = StagePrototype.objects.filter(type="service", name=item["service"]).first()
            if not stage_proto:
                msg = 'Unknown service "{}" {}'
                err("INVALID_ACTION_DEFINITION", msg.format(item["service"], ref))
            if not StagePrototype.objects.filter(parent=stage_proto, type="component", name=item["component"]):
                msg = 'Unknown component "{}" of service "{}" {}'
                err(
                    "INVALID_ACTION_DEFINITION",
                    msg.format(item["component"], stage_proto.name, ref),
                )


def check_component_requires(comp):
    if not comp.requires:
        return
    ref = f'in requires of component "{comp.name}" of {proto_ref(comp.parent)}'
    req_list = comp.requires
    for i, item in enumerate(req_list):
        if "service" in item:
            service = StagePrototype.obj.get(name=item["service"], type="service")
        else:
            service = comp.parent
            req_list[i]["service"] = comp.parent.name
        req_comp = StagePrototype.obj.get(name=item["component"], type="component", parent=service)
        if comp == req_comp:
            msg = "Component can not require themself {}"
            err("COMPONENT_CONSTRAINT_ERROR", msg.format(ref))
    comp.requires = req_list
    comp.save()


def check_bound_component(comp):
    if not comp.bound_to:
        return
    ref = f'in "bound_to" of component "{comp.name}" of {proto_ref(comp.parent)}'
    bind = comp.bound_to
    service = StagePrototype.obj.get(name=bind["service"], type="service")
    bind_comp = StagePrototype.obj.get(name=bind["component"], type="component", parent=service)
    if comp == bind_comp:
        msg = "Component can not require themself {}"
        err("COMPONENT_CONSTRAINT_ERROR", msg.format(ref))


def re_check_components():
    for comp in StagePrototype.objects.filter(type="component"):
        check_component_requires(comp)
        check_bound_component(comp)


def check_variant_host(args, ref):
    def check_predicate(predicate, args):
        if predicate == "in_service":
            StagePrototype.obj.get(type="service", name=args["service"])
        elif predicate == "in_component":
            service = StagePrototype.obj.get(type="service", name=args["service"])
            StagePrototype.obj.get(type="component", name=args["component"], parent=service)

    if args is None:
        return
    if isinstance(args, dict):
        if "predicate" not in args:
            return
        check_predicate(args["predicate"], args["args"])
        check_variant_host(args["args"], ref)
    if isinstance(args, list):
        for i in args:
            check_predicate(i["predicate"], i["args"])
            check_variant_host(i["args"], ref)


def re_check_config():
    for c in StagePrototypeConfig.objects.filter(type="variant"):
        ref = proto_ref(c.prototype)
        lim = c.limits
        if lim["source"]["type"] == "list":
            keys = lim["source"]["name"].split("/")
            name = keys[0]
            subname = ""
            if len(keys) > 1:
                subname = keys[1]
            try:
                s = StagePrototypeConfig.objects.get(prototype=c.prototype, name=name, subname=subname)
            except StagePrototypeConfig.DoesNotExist:
                msg = f'Unknown config source name "{{}}" for {ref} config "{c.name}/{c.subname}"'
                err("INVALID_CONFIG_DEFINITION", msg.format(lim["source"]["name"]))
            if s == c:
                msg = f'Config parameter "{c.name}/{c.subname}" can not refer to itself ({ref})'
                err("INVALID_CONFIG_DEFINITION", msg)
        elif lim["source"]["type"] == "builtin":
            if not lim["source"]["args"]:
                continue
            if lim["source"]["name"] == "host":
                msg = f'in source:args of {ref} config "{c.name}/{c.subname}"'
                check_variant_host(lim["source"]["args"], msg)
            if "service" in lim["source"]["args"]:
                service = lim["source"]["args"]["service"]
                try:
                    sp_service = StagePrototype.objects.get(type="service", name=service)
                except StagePrototype.DoesNotExist:
                    msg = 'Service "{}" in source:args of {} config "{}/{}" does not exists'
                    err("INVALID_CONFIG_DEFINITION", msg.format(service, ref, c.name, c.subname))
            if "component" in lim["source"]["args"]:
                comp = lim["source"]["args"]["component"]
                try:
                    StagePrototype.objects.get(type="component", name=comp, parent=sp_service)
                except StagePrototype.DoesNotExist:
                    msg = 'Component "{}" in source:args of {} config "{}/{}" does not exists'
                    err("INVALID_CONFIG_DEFINITION", msg.format(comp, ref, c.name, c.subname))


def second_pass():
    re_check_actions()
    re_check_components()
    re_check_config()


def copy_stage_prototype(stage_prototypes, bundle):
    prototypes = []  # Map for stage prototype id: new prototype
    for sp in stage_prototypes:
        proto = copy_obj(
            sp,
            Prototype,
            (
                "type",
                "path",
                "name",
                "version",
                "required",
                "shared",
                "license_path",
                "license_hash",
                "monitoring",
                "display_name",
                "description",
                "adcm_min_version",
                "venv",
                "config_group_customization",
                "allow_maintenance_mode",
            ),
        )
        if proto.license_path:
            proto.license = "unaccepted"
            if check_license(proto):
                proto.license = "accepted"
        proto.bundle = bundle
        prototypes.append(proto)
    Prototype.objects.bulk_create(prototypes)


def copy_stage_upgrade(stage_upgrades, bundle):
    upgrades = []
    for su in stage_upgrades:
        upg = copy_obj(
            su,
            Upgrade,
            (
                "name",
                "description",
                "min_version",
                "max_version",
                "min_strict",
                "max_strict",
                "state_available",
                "state_on_success",
                "from_edition",
            ),
        )
        upg.bundle = bundle
        upgrades.append(upg)
        if su.action:
            prototype = Prototype.objects.get(name=su.action.prototype.name, bundle=bundle)
            upg.action = Action.objects.get(prototype=prototype, name=su.action.name)
    Upgrade.objects.bulk_create(upgrades)


def prepare_bulk(origin_objects, Target, prototype, fields):
    target_objects = []
    for oo in origin_objects:
        to = copy_obj(oo, Target, fields)
        to.prototype = prototype
        target_objects.append(to)
    return target_objects


def copy_stage_actions(stage_actions, prototype):
    actions = prepare_bulk(
        stage_actions,
        Action,
        prototype,
        (
            "name",
            "type",
            "script",
            "script_type",
            "state_available",
            "state_unavailable",
            "state_on_success",
            "state_on_fail",
            "multi_state_available",
            "multi_state_unavailable",
            "multi_state_on_success_set",
            "multi_state_on_success_unset",
            "multi_state_on_fail_set",
            "multi_state_on_fail_unset",
            "params",
            "log_files",
            "hostcomponentmap",
            "display_name",
            "description",
            "ui_options",
            "allow_to_terminate",
            "partial_execution",
            "host_action",
            "venv",
            "allow_in_maintenance_mode",
        ),
    )
    Action.objects.bulk_create(actions)


def copy_stage_sub_actons(bundle):
    sub_actions = []
    for ssubaction in StageSubAction.objects.all():
        if ssubaction.action.prototype.type == "component":
            parent = Prototype.objects.get(
                bundle=bundle,
                type="service",
                name=ssubaction.action.prototype.parent.name,
            )
        else:
            parent = None
        action = Action.objects.get(
            prototype__bundle=bundle,
            prototype__type=ssubaction.action.prototype.type,
            prototype__name=ssubaction.action.prototype.name,
            prototype__parent=parent,
            prototype__version=ssubaction.action.prototype.version,
            name=ssubaction.action.name,
        )
        sub = copy_obj(
            ssubaction,
            SubAction,
            (
                "name",
                "display_name",
                "script",
                "script_type",
                "state_on_fail",
                "multi_state_on_fail_set",
                "multi_state_on_fail_unset",
                "params",
                "allow_to_terminate",
            ),
        )
        sub.action = action
        sub_actions.append(sub)
    SubAction.objects.bulk_create(sub_actions)


def copy_stage_component(stage_components, stage_proto, prototype, bundle):
    componets = []
    for c in stage_components:
        comp = copy_obj(
            c,
            Prototype,
            (
                "type",
                "path",
                "name",
                "version",
                "required",
                "monitoring",
                "bound_to",
                "constraint",
                "requires",
                "display_name",
                "description",
                "adcm_min_version",
                "config_group_customization",
                "venv",
            ),
        )
        comp.bundle = bundle
        comp.parent = prototype
        componets.append(comp)
    Prototype.objects.bulk_create(componets)
    for sp in StagePrototype.objects.filter(type="component", parent=stage_proto):
        proto = Prototype.objects.get(name=sp.name, type="component", parent=prototype, bundle=bundle)
        copy_stage_actions(StageAction.objects.filter(prototype=sp), proto)
        copy_stage_config(StagePrototypeConfig.objects.filter(prototype=sp), proto)


def copy_stage_import(stage_imports, prototype):
    imports = prepare_bulk(
        stage_imports,
        PrototypeImport,
        prototype,
        (
            "name",
            "min_version",
            "max_version",
            "min_strict",
            "max_strict",
            "default",
            "required",
            "multibind",
        ),
    )
    PrototypeImport.objects.bulk_create(imports)


def copy_stage_config(stage_config, prototype):
    target_config = []
    for sc in stage_config:
        c = copy_obj(
            sc,
            PrototypeConfig,
            (
                "name",
                "subname",
                "default",
                "type",
                "description",
                "display_name",
                "limits",
                "required",
                "ui_options",
                "group_customization",
            ),
        )
        if sc.action:
            c.action = Action.objects.get(prototype=prototype, name=sc.action.name)
        c.prototype = prototype
        target_config.append(c)
    PrototypeConfig.objects.bulk_create(target_config)


def check_license(proto):
    return Prototype.objects.filter(license_hash=proto.license_hash, license="accepted").exists()


def copy_stage(bundle_hash, bundle_proto):
    bundle = copy_obj(
        bundle_proto,
        Bundle,
        ("name", "version", "edition", "description"),
    )
    bundle.hash = bundle_hash
    try:
        bundle.save()
    except IntegrityError:
        shutil.rmtree(settings.BUNDLE_DIR / bundle.hash)
        msg = 'Bundle "{}" {} already installed'
        err("BUNDLE_ERROR", msg.format(bundle_proto.name, bundle_proto.version))

    stage_prototypes = StagePrototype.objects.exclude(type="component")
    copy_stage_prototype(stage_prototypes, bundle)

    for sp in stage_prototypes:
        proto = Prototype.objects.get(name=sp.name, type=sp.type, bundle=bundle)
        copy_stage_actions(StageAction.objects.filter(prototype=sp), proto)
        copy_stage_config(StagePrototypeConfig.objects.filter(prototype=sp), proto)
        copy_stage_component(StagePrototype.objects.filter(parent=sp, type="component"), sp, proto, bundle)
        for se in StagePrototypeExport.objects.filter(prototype=sp):
            pe = PrototypeExport(prototype=proto, name=se.name)
            pe.save()
        copy_stage_import(StagePrototypeImport.objects.filter(prototype=sp), proto)

    copy_stage_sub_actons(bundle)
    copy_stage_upgrade(StageUpgrade.objects.all(), bundle)
    return bundle


def update_bundle_from_stage(
    bundle,
):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    for sp in StagePrototype.objects.all():
        try:
            p = Prototype.objects.get(bundle=bundle, type=sp.type, name=sp.name, version=sp.version)
            p.path = sp.path
            p.version = sp.version
            p.description = sp.description
            p.display_name = sp.display_name
            p.required = sp.required
            p.shared = sp.shared
            p.monitoring = sp.monitoring
            p.adcm_min_version = sp.adcm_min_version
            p.venv = sp.venv
            p.config_group_customization = sp.config_group_customization
            p.allow_maintenance_mode = sp.allow_maintenance_mode
        except Prototype.DoesNotExist:
            p = copy_obj(
                sp,
                Prototype,
                (
                    "type",
                    "path",
                    "name",
                    "version",
                    "required",
                    "shared",
                    "monitoring",
                    "bound_to",
                    "constraint",
                    "requires",
                    "display_name",
                    "description",
                    "adcm_min_version",
                    "venv",
                    "config_group_customization",
                    "allow_maintenance_mode",
                ),
            )
            p.bundle = bundle
        p.save()
        for saction in StageAction.objects.filter(prototype=sp):
            try:
                action = Action.objects.get(prototype=p, name=saction.name)
                update_obj(
                    action,
                    saction,
                    (
                        "type",
                        "script",
                        "script_type",
                        "state_available",
                        "state_on_success",
                        "state_on_fail",
                        "multi_state_available",
                        "multi_state_on_success_set",
                        "multi_state_on_success_unset",
                        "multi_state_on_fail_set",
                        "multi_state_on_fail_unset",
                        "params",
                        "log_files",
                        "hostcomponentmap",
                        "display_name",
                        "description",
                        "ui_options",
                        "allow_to_terminate",
                        "partial_execution",
                        "host_action",
                        "venv",
                        "allow_in_maintenance_mode",
                    ),
                )
            except Action.DoesNotExist:
                action = copy_obj(
                    saction,
                    Action,
                    (
                        "name",
                        "type",
                        "script",
                        "script_type",
                        "state_available",
                        "state_on_success",
                        "state_on_fail",
                        "multi_state_available",
                        "multi_state_on_success_set",
                        "multi_state_on_success_unset",
                        "multi_state_on_fail_set",
                        "multi_state_on_fail_unset",
                        "params",
                        "log_files",
                        "hostcomponentmap",
                        "display_name",
                        "description",
                        "ui_options",
                        "allow_to_terminate",
                        "partial_execution",
                        "host_action",
                        "venv",
                        "allow_in_maintenance_mode",
                    ),
                )
                action.prototype = p
            action.save()
            SubAction.objects.filter(action=action).delete()
            for ssubaction in StageSubAction.objects.filter(action=saction):
                sub = copy_obj(
                    ssubaction,
                    SubAction,
                    (
                        "script",
                        "script_type",
                        "state_on_fail",
                        "multi_state_on_fail_set",
                        "multi_state_on_fail_unset",
                        "params",
                    ),
                )
                sub.action = action
                sub.save()
        for sc in StagePrototypeConfig.objects.filter(prototype=sp):
            flist = (
                "default",
                "type",
                "description",
                "display_name",
                "limits",
                "required",
                "ui_options",
                "group_customization",
            )
            act = None
            if sc.action:
                act = Action.objects.get(prototype=p, name=sc.action.name)
            try:
                pconfig = PrototypeConfig.objects.get(prototype=p, action=act, name=sc.name, subname=sc.subname)
                update_obj(pconfig, sc, flist)
            except PrototypeConfig.DoesNotExist:
                pconfig = copy_obj(sc, PrototypeConfig, ("name", "subname") + flist)
                pconfig.action = act
                pconfig.prototype = p
            pconfig.save()

        PrototypeExport.objects.filter(prototype=p).delete()
        for se in StagePrototypeExport.objects.filter(prototype=sp):
            pe = PrototypeExport(prototype=p, name=se.name)
            pe.save()
        PrototypeImport.objects.filter(prototype=p).delete()
        for si in StagePrototypeImport.objects.filter(prototype=sp):
            pi = copy_obj(
                si,
                PrototypeImport,
                (
                    "name",
                    "min_version",
                    "max_version",
                    "min_strict",
                    "max_strict",
                    "default",
                    "required",
                    "multibind",
                ),
            )
            pi.prototype = p
            pi.save()

    Upgrade.objects.filter(bundle=bundle).delete()
    for su in StageUpgrade.objects.all():
        upg = copy_obj(
            su,
            Upgrade,
            (
                "name",
                "description",
                "min_version",
                "max_version",
                "min_strict",
                "max_strict",
                "state_available",
                "state_on_success",
                "from_edition",
            ),
        )
        upg.bundle = bundle
        upg.save()


def clear_stage():
    for model in STAGE:
        model.objects.all().delete()


def delete_bundle(bundle):
    providers = HostProvider.objects.filter(prototype__bundle=bundle)
    if providers:
        p = providers[0]
        msg = 'There is provider #{} "{}" of bundle #{} "{}" {}'
        err("BUNDLE_CONFLICT", msg.format(p.id, p.name, bundle.id, bundle.name, bundle.version))
    clusters = Cluster.objects.filter(prototype__bundle=bundle)
    if clusters:
        cl = clusters[0]
        msg = 'There is cluster #{} "{}" of bundle #{} "{}" {}'
        err("BUNDLE_CONFLICT", msg.format(cl.id, cl.name, bundle.id, bundle.name, bundle.version))
    adcm = ADCM.objects.filter(prototype__bundle=bundle)
    if adcm:
        msg = 'There is adcm object of bundle #{} "{}" {}'
        err("BUNDLE_CONFLICT", msg.format(bundle.id, bundle.name, bundle.version))
    if bundle.hash != "adcm":
        try:
            shutil.rmtree(Path(settings.BUNDLE_DIR, bundle.hash))
        except FileNotFoundError:
            logger.info(
                "Bundle %s %s was removed in file system. Delete bundle in database",
                bundle.name,
                bundle.version,
            )
    bundle_id = bundle.id
    bundle.delete()
    for role in Role.objects.filter(class_name="ParentRole"):
        if not role.child.all():
            role.delete()
    ProductCategory.re_collect()
    cm.status_api.post_event("delete", "bundle", bundle_id)


def check_services():
    s = {}
    for p in StagePrototype.objects.filter(type="service"):
        if p.name in s:
            msg = "There are more than one service with name {}"
            err("BUNDLE_ERROR", msg.format(p.name))
        s[p.name] = p.version


def check_adcm_version(bundle):
    if not bundle.adcm_min_version:
        return
    if rpm.compare_versions(bundle.adcm_min_version, settings.ADCM_VERSION) > 0:
        msg = "This bundle required ADCM version equal to {} or newer."
        err("BUNDLE_VERSION_ERROR", msg.format(bundle.adcm_min_version))


def get_stage_bundle(bundle_file):
    clusters = StagePrototype.objects.filter(type="cluster")
    providers = StagePrototype.objects.filter(type="provider")
    if clusters:
        if len(clusters) > 1:
            msg = 'There are more than one ({}) cluster definition in bundle "{}"'
            err("BUNDLE_ERROR", msg.format(len(clusters), bundle_file))
        if providers:
            msg = 'There are {} host provider definition in cluster type bundle "{}"'
            err("BUNDLE_ERROR", msg.format(len(providers), bundle_file))
        hosts = StagePrototype.objects.filter(type="host")
        if hosts:
            msg = 'There are {} host definition in cluster type bundle "{}"'
            err("BUNDLE_ERROR", msg.format(len(hosts), bundle_file))
        check_services()
        bundle = clusters[0]
    elif providers:
        if len(providers) > 1:
            msg = 'There are more than one ({}) host provider definition in bundle "{}"'
            err("BUNDLE_ERROR", msg.format(len(providers), bundle_file))
        services = StagePrototype.objects.filter(type="service")
        if services:
            msg = 'There are {} service definition in host provider type bundle "{}"'
            err("BUNDLE_ERROR", msg.format(len(services), bundle_file))
        hosts = StagePrototype.objects.filter(type="host")
        if not hosts:
            msg = 'There isn\'t any host definition in host provider type bundle "{}"'
            err("BUNDLE_ERROR", msg.format(bundle_file))
        bundle = providers[0]
    else:
        msg = 'There isn\'t any cluster or host provider definition in bundle "{}"'
        err("BUNDLE_ERROR", msg.format(bundle_file))
    check_adcm_version(bundle)
    return bundle
