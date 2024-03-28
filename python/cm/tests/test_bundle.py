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
import json

from adcm.tests.base import APPLICATION_JSON, BaseTestCase, BundleLogicMixin
from django.conf import settings
from django.db import IntegrityError
from django.urls import reverse
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_409_CONFLICT,
)

from cm.adcm_config.ansible import ansible_decrypt
from cm.api import delete_host_provider
from cm.bundle import delete_bundle
from cm.errors import AdcmEx
from cm.models import Bundle, ConfigLog, SubAction
from cm.services.bundle import detect_path_for_file_in_bundle
from cm.tests.test_upgrade import (
    cook_cluster,
    cook_cluster_bundle,
    cook_provider,
    cook_provider_bundle,
)


class TestBundle(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.test_files_dir = self.base_dir / "python" / "cm" / "tests" / "files"

    def test_path_resolution(self) -> None:
        bundle_root = Path(__file__).parent / "files" / "files_with_symlinks"
        inner_dir = Path("inside")

        result = detect_path_for_file_in_bundle(bundle_root=bundle_root, config_yaml_dir=Path(), file="somefile")
        self.assertEqual(result, bundle_root / "somefile")

        result = detect_path_for_file_in_bundle(bundle_root=bundle_root, config_yaml_dir=inner_dir, file="./somefile")
        self.assertEqual(result, bundle_root / "inside" / "somefile")

        result = detect_path_for_file_in_bundle(bundle_root=bundle_root, config_yaml_dir=inner_dir, file="./backref")
        self.assertEqual(result, bundle_root / "inside" / "backref")

        result = detect_path_for_file_in_bundle(bundle_root=bundle_root, config_yaml_dir=Path(), file="inside/backref")
        self.assertEqual(result, bundle_root / "inside" / "backref")

        result = detect_path_for_file_in_bundle(bundle_root=bundle_root, config_yaml_dir=Path(), file="./another_link")
        self.assertEqual(result, bundle_root / "another_link")

    def test_bundle_upload_duplicate_upgrade_fail(self):
        with self.assertRaises(IntegrityError):
            self.upload_and_load_bundle(path=Path(self.test_files_dir, "test_upgrade_duplicated.tar"))

    def test_bundle_upload_upgrade_different_upgrade_name_success(self):
        self.upload_and_load_bundle(path=Path(self.test_files_dir, "test_upgrade_different_name.tar"))

    def test_bundle_upload_upgrade_different_from_edition_success(self):
        self.upload_and_load_bundle(path=Path(self.test_files_dir, "test_upgrade_different_from_edition.tar"))

    def test_bundle_upload_upgrade_different_min_version_success(self):
        self.upload_and_load_bundle(path=Path(self.test_files_dir, "test_upgrade_different_min_version.tar"))

    def test_bundle_upload_upgrade_different_max_strict_success(self):
        self.upload_and_load_bundle(path=Path(self.test_files_dir, "test_upgrade_different_max_strict.tar"))

    def test_bundle_upload_upgrade_different_state_available_success(self):
        self.upload_and_load_bundle(path=Path(self.test_files_dir, "test_upgrade_different_state_available.tar"))

    def test_bundle_upload_upgrade_different_state_on_success_success(self):
        self.upload_and_load_bundle(path=Path(self.test_files_dir, "test_upgrade_different_state_on_success.tar"))

    def test_secretfile(self):
        bundle, cluster, config_log = self.upload_bundle_create_cluster_config_log(
            bundle_path=Path(
                self.base_dir,
                "python/cm/tests/files/config_cluster_secretfile_secretmap.tar",
            ),
        )

        with open(file=Path(settings.BUNDLE_DIR, bundle.hash, "secretfile"), encoding=settings.ENCODING_UTF_8) as f:
            secret_file_bundle_content = f.read()

        self.assertNotIn(settings.ANSIBLE_VAULT_HEADER, secret_file_bundle_content)

        with open(
            file=Path(settings.FILE_DIR, f"cluster.{cluster.pk}.secretfile."),
            encoding=settings.ENCODING_UTF_8,
        ) as f:
            secret_file_content = f.read()

        self.assertEqual(secret_file_bundle_content, secret_file_content)

        new_content = "new content"
        config_log.config["secretfile"] = "new content"

        response: Response = self.client.post(
            path=reverse(viewname="v1:config-log-list"),
            data={"obj_ref": cluster.config.pk, "config": json.dumps(config_log.config)},
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)

        new_config_log = ConfigLog.objects.filter(obj_ref=cluster.config).order_by("pk").last()

        self.assertEqual(new_content, ansible_decrypt(msg=new_config_log.config["secretfile"]))

    def test_secretfile_update_config(self):
        _, cluster, _ = self.upload_bundle_create_cluster_config_log(
            bundle_path=Path(
                self.base_dir,
                "python/cm/tests/files/test_secretfile_update_config.tar",
            ),
        )

        secretfile_bundle_content = "aaa"
        secretfile_group_bundle_content = "bbb"
        response: Response = self.client.post(
            path=reverse(viewname="v1:config-history", kwargs={"cluster_id": cluster.pk}),
            params={"view": "interface"},
            data={
                "config": {
                    "password": "aaa",
                    "secrettext": "aaa",
                    "secretmap": {"aaa": "aaa"},
                    "secretfile": secretfile_bundle_content,
                    "group": {
                        "password": "aaa",
                        "secrettext": "aaa",
                        "secretmap": {"aaa": "aaa"},
                        "secretfile": secretfile_group_bundle_content,
                    },
                },
                "attr": {},
            },
            content_type=APPLICATION_JSON,
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)

        with open(
            file=Path(settings.FILE_DIR, f"cluster.{cluster.pk}.secretfile."),
            encoding=settings.ENCODING_UTF_8,
        ) as f:
            secret_file_content = f.read()

        self.assertEqual(secretfile_bundle_content, secret_file_content)

        response: Response = self.client.get(
            path=reverse(viewname="v1:config-current", kwargs={"cluster_id": cluster.pk})
        )

        self.assertIn(settings.ANSIBLE_VAULT_HEADER, response.data["config"]["secretfile"])
        self.assertEqual(ansible_decrypt(msg=response.data["config"]["secretfile"]), secretfile_bundle_content)
        self.assertEqual(
            ansible_decrypt(msg=response.data["config"]["group"]["secretfile"]),
            secretfile_group_bundle_content,
        )

    def test_secretmap(self):
        _, cluster, config_log = self.upload_bundle_create_cluster_config_log(
            bundle_path=Path(
                self.base_dir,
                "python/cm/tests/files/config_cluster_secretfile_secretmap.tar",
            ),
        )

        self.assertIn(settings.ANSIBLE_VAULT_HEADER, config_log.config["secretmap"]["key"])
        self.assertEqual("value", ansible_decrypt(config_log.config["secretmap"]["key"]))

        new_value = "new value"
        config_log.config["secretmap"]["key"] = "new value"

        response: Response = self.client.post(
            path=reverse(viewname="v1:config-log-list"),
            data={"obj_ref": cluster.config.pk, "config": json.dumps(config_log.config)},
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)

        new_config_log = ConfigLog.objects.filter(obj_ref=cluster.config).order_by("pk").last()

        self.assertIn(settings.ANSIBLE_VAULT_HEADER, new_config_log.config["secretmap"]["key"])
        self.assertEqual(new_value, ansible_decrypt(new_config_log.config["secretmap"]["key"]))

    def test_secretmap_no_default(self):
        self.upload_bundle_create_cluster_config_log(
            bundle_path=Path(
                self.base_dir,
                "python/cm/tests/files/test_secret_config_v10_community.tar",
            ),
        )

    def test_secretmap_no_default1(self):
        self.upload_bundle_create_cluster_config_log(
            bundle_path=Path(
                self.base_dir,
                "python/cm/tests/files/test_secret_config_v12_community.tar",
            ),
        )

    def test_cluster_bundle_deletion(self):
        bundle = cook_cluster_bundle("1.0")
        cook_cluster(bundle, "TestCluster")
        try:
            delete_bundle(bundle)
        except AdcmEx as e:
            self.assertEqual(e.code, "BUNDLE_CONFLICT")

    def test_provider_bundle_deletion(self):
        bundle = cook_provider_bundle("1.0")
        provider = cook_provider(bundle, "TestProvider")
        try:
            delete_bundle(bundle)
        except AdcmEx as e:
            self.assertEqual(e.code, "BUNDLE_CONFLICT")

        try:
            delete_host_provider(provider)
        except AdcmEx as e:
            self.assertEqual(e.code, "PROVIDER_CONFLICT")

    def test_duplicate_component_name_fail(self):
        path = Path(self.test_files_dir, "test_duplicate_component_name.tar")
        self.upload_bundle(path=path)

        response: Response = self.client.post(
            path=reverse(viewname="v1:load-bundle"),
            data={"bundle_file": path.name},
        )

        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["desc"],
            "Display name for component within one service must be unique."
            ' Incorrect definition of component "component_2" 3.0',
        )

    def test_upload_hc_acl_cluster_action_without_service_fail(self):
        path = Path(self.test_files_dir, "test_cluster_hc_acl_without_service.tar")
        self.upload_bundle(path=path)

        response = self.client.post(path=reverse(viewname="v1:load-bundle"), data={"bundle_file": path.name})

        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertEqual(response.data["code"], "INVALID_ACTION_DEFINITION")
        self.assertEqual(
            response.data["desc"],
            '"service" filed is required in hc_acl of action "sleep" '
            'of cluster "hc_acl_in_cluster_without_service" 1.0',
        )

    def test_upload_hc_acl_service_action_without_service_success(self):
        path = Path(self.test_files_dir, "test_service_hc_acl_without_service.tar")
        self.upload_bundle(path=path)

        response = self.client.post(path=reverse(viewname="v1:load-bundle"), data={"bundle_file": path.name})

        self.assertEqual(response.status_code, HTTP_200_OK)

    def test_upload_hc_acl_component_action_without_service_fail(self):
        path = Path(self.test_files_dir, "test_component_hc_acl_without_service.tar")
        self.upload_bundle(path=path)

        response = self.client.post(path=reverse(viewname="v1:load-bundle"), data={"bundle_file": path.name})

        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertEqual(response.data["code"], "INVALID_ACTION_DEFINITION")
        self.assertEqual(
            response.data["desc"],
            '"service" filed is required in hc_acl of action "sleep" of component "component" 1.0',
        )


class TestBundleParsing(BaseTestCase, BundleLogicMixin):
    def get_ordered_subs(self, bundle: Bundle, action_name: str):
        return SubAction.objects.filter(action__name=action_name, action__prototype__bundle=bundle).order_by("id")

    def test_params_in_action_processing_during_upload(self) -> None:
        bundle = self.add_bundle(
            source_dir=self.base_dir / "python" / "cm" / "tests" / "bundles" / "cluster_various_params_in_actions"
        )
        fields = ("name", "params")

        subs = self.get_ordered_subs(action_name="job_no_params", bundle=bundle)
        self.assertEqual(subs.count(), 1)
        self.assertEqual(list(subs.values_list(*fields)), [("job_no_params", {})])

        subs = self.get_ordered_subs(action_name="job_params", bundle=bundle)
        self.assertEqual(subs.count(), 1)
        self.assertEqual(
            list(subs.values_list(*fields)), [("job_params", {"ansible_tags": "hello, there", "custom": [4, 3]})]
        )

        subs = self.get_ordered_subs(action_name="task_no_params", bundle=bundle)
        self.assertEqual(subs.count(), 2)
        self.assertEqual(list(subs.values_list(*fields)), [("first", {}), ("second", {})])

        subs = self.get_ordered_subs(action_name="task_params_in_action", bundle=bundle)
        self.assertEqual(subs.count(), 2)
        action_params = {"jinja2_native": True, "custom": {"key": "value"}}
        self.assertEqual(list(subs.values_list(*fields)), [("first", action_params), ("second", action_params)])

        subs = self.get_ordered_subs(action_name="task_params_in_action_and_scripts", bundle=bundle)
        self.assertEqual(subs.count(), 2)
        self.assertEqual(
            list(subs.values_list(*fields)),
            [("first", {"ansible_tags": "one, two", "jinja2_native": "hello"}), ("second", action_params)],
        )

        subs = self.get_ordered_subs(action_name="task_params_in_action_and_all_scripts", bundle=bundle)
        self.assertEqual(subs.count(), 2)
        self.assertEqual(
            list(subs.values_list(*fields)),
            [("first", {"ansible_tags": "one, two", "jinja2_native": "hello"}), ("second", {"perfect": "thing"})],
        )

        subs = self.get_ordered_subs(action_name="task_params_in_scripts", bundle=bundle)
        self.assertEqual(subs.count(), 2)
        self.assertEqual(
            list(subs.values_list(*fields)), [("first", {"ansible_tags": "one"}), ("second", {"perfect": "thing"})]
        )
