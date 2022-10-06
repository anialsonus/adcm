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
# pylint: disable=too-many-lines

import os
import string

from django.conf import settings
from django.urls import reverse
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_204_NO_CONTENT,
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
)

from adcm.tests.base import APPLICATION_JSON, BaseTestCase
from cm.models import Bundle, Cluster, Host, HostProvider, Prototype


class TestHostAPI(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.incorrect_values = {
            "a" * 254,
            ".startwithdot",
            "-startwithhypen",
            "contain space",
            "have!exclamation",
            "have_underscore",
        }
        self.correct_values = {
            "a" * 253,
            "StartWithChar",
            "0StartWithNumber99",
            "EndWithDot.",
            "Contain-Hyphen.Dot",
        }

        self.files_dir = settings.BASE_DIR / "python" / "cm" / "tests" / "files"
        self.bundle_ssh_name = "ssh.1.0.tar"
        self.load_bundle(self.bundle_ssh_name)
        self.provider = HostProvider.objects.create(
            name="test_provider",
            prototype=Prototype.objects.all()[1],
        )
        self.host = Host.objects.create(
            fqdn="test-fqdn",
            prototype=Prototype.objects.all()[0],
            provider=self.provider,
            maintenance_mode=True,
        )

    def load_bundle(self, bundle_name):
        with open(os.path.join(self.files_dir, bundle_name), encoding="utf-8") as f:
            response: Response = self.client.post(
                path=reverse("upload-bundle"),
                data={"file": f},
            )

        self.assertEqual(response.status_code, HTTP_201_CREATED)

        response: Response = self.client.post(
            path=reverse("load-bundle"),
            data={"bundle_file": bundle_name},
        )

        self.assertEqual(response.status_code, HTTP_200_OK)

    def create_host_in_cluster(self, name: str, mm_allowed: bool) -> Host:
        cluster_proto_mm_allowed = Prototype.objects.create(
            name=f"proto_for_{name}",
            type="cluster",
            bundle=Bundle.objects.create(name=f"bundle_for_{name}_mm_{mm_allowed}"),
            allow_maintenance_mode=mm_allowed,
        )
        cluster = Cluster.objects.create(name=name, prototype=cluster_proto_mm_allowed)
        return Host.objects.create(
            fqdn=f"host-{name}",
            prototype=Prototype.objects.all()[0],
            maintenance_mode=False,
            cluster=cluster,
        )

    def get_host_proto_id(self):
        response: Response = self.client.get(reverse("host-type"))

        self.assertEqual(response.status_code, HTTP_200_OK)

        for host in response.json():
            return host["bundle_id"], host["id"]

    def get_host_provider_proto_id(self):
        response: Response = self.client.get(reverse("provider-type"))

        self.assertEqual(response.status_code, HTTP_200_OK)

        for provider in response.json():
            return provider["bundle_id"], provider["id"]

    def check_incorrect_fqdn_update(self, response: Response, expected_fqdn: str):
        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        err = response.json()
        if "code" in err:
            self.assertEqual(err["code"], "WRONG_NAME")
        else:
            self.assertIn("fqdn", err)
            self.assertEqual(err["fqdn"], ["Ensure this field has no more than 253 characters."])
        self.host.refresh_from_db()
        self.assertEqual(self.host.fqdn, expected_fqdn)

    def check_success_fqdn_update(self, response: Response, expected_fqdn: str):
        self.assertEqual(response.status_code, HTTP_200_OK)
        self.host.refresh_from_db()
        self.assertEqual(self.host.fqdn, expected_fqdn)

    def check_is_maintenance_mode_allowed(self, host: Host, expected: bool):
        field = "is_maintenance_mode_available"
        response = self.client.get(reverse("host-details", args=[host.pk]))
        self.assertEqual(response.status_code, HTTP_200_OK)
        body = response.json()
        self.assertEqual(body[field], expected)

        response = self.client.get(reverse("host"))
        self.assertEqual(response.status_code, HTTP_200_OK)
        body = response.json()
        host_to_check = next(filter(lambda h: h["id"] == host.pk, body))
        self.assertEqual(host_to_check[field], expected)

    def test_host(self):  # pylint: disable=too-many-statements
        host = "test.server.net"
        host_url = reverse("host")

        # self.load_bundle(self.bundle_ssh_name)
        ssh_bundle_id, host_proto = self.get_host_proto_id()

        response: Response = self.client.post(host_url, {})

        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["fqdn"], ["This field is required."])

        response: Response = self.client.post(
            host_url, {"fqdn": host, "prototype_id": host_proto, "provider_id": 0}
        )

        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)
        self.assertEqual(response.json()["code"], "PROVIDER_NOT_FOUND")

        _, provider_proto = self.get_host_provider_proto_id()
        response: Response = self.client.post(
            path=reverse("provider"), data={"name": "DF1", "prototype_id": provider_proto}
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)

        provider_id = response.json()["id"]

        response: Response = self.client.post(
            host_url, {"fqdn": host, "prototype_id": 42, "provider_id": provider_id}
        )

        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)
        self.assertEqual(response.json()["code"], "PROTOTYPE_NOT_FOUND")

        response: Response = self.client.post(host_url, {"fqdn": host, "provider_id": provider_id})

        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["prototype_id"], ["This field is required."])

        response: Response = self.client.post(host_url, {"fqdn": host, "prototype_id": host_proto})

        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["provider_id"], ["This field is required."])

        response: Response = self.client.post(
            host_url,
            {
                "fqdn": f"x{'deadbeef' * 32}",  # 257 chars
                "prototype_id": host_proto,
                "provider_id": provider_id,
            },
        )
        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        self.assertIn("fqdn", response.json())

        response: Response = self.client.post(
            host_url,
            {
                "fqdn": f"x{string.punctuation}",
                "prototype_id": host_proto,
                "provider_id": provider_id,
            },
        )

        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["code"], "WRONG_NAME")

        response: Response = self.client.post(
            host_url, {"fqdn": host, "prototype_id": host_proto, "provider_id": provider_id}
        )

        self.assertEqual(response.status_code, HTTP_201_CREATED)

        host_id = response.json()["id"]

        this_host_url = reverse("host-details", kwargs={"host_id": host_id})

        response: Response = self.client.get(this_host_url)

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.json()["fqdn"], host)

        response: Response = self.client.put(this_host_url, {}, content_type=APPLICATION_JSON)

        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.json(),
            {
                "prototype_id": ["This field is required."],
                "provider_id": ["This field is required."],
                "fqdn": ["This field is required."],
                "maintenance_mode": ["This field is required."],
            },
        )

        response: Response = self.client.post(
            host_url, {"fqdn": host, "prototype_id": host_proto, "provider_id": provider_id}
        )

        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "HOST_CONFLICT")

        response: Response = self.client.delete(this_host_url)

        self.assertEqual(response.status_code, HTTP_204_NO_CONTENT)

        response: Response = self.client.get(this_host_url)

        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)
        self.assertEqual(response.json()["code"], "HOST_NOT_FOUND")

        response: Response = self.client.delete(this_host_url)

        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)
        self.assertEqual(response.json()["code"], "HOST_NOT_FOUND")

        response: Response = self.client.delete(
            path=reverse("bundle-details", kwargs={"bundle_id": ssh_bundle_id})
        )

        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "BUNDLE_CONFLICT")

        response: Response = self.client.delete(
            path=reverse("provider-details", kwargs={"provider_id": provider_id})
        )

        self.assertEqual(response.status_code, HTTP_204_NO_CONTENT)

        self.provider.delete()
        response: Response = self.client.delete(
            path=reverse("bundle-details", kwargs={"bundle_id": ssh_bundle_id})
        )

        self.assertEqual(response.status_code, HTTP_204_NO_CONTENT)

    def test_host_update_fqdn_success(self):
        new_test_fqdn = "new-test-fqdn"

        response: Response = self.client.patch(
            path=reverse("host-details", kwargs={"host_id": self.host.pk}),
            data={"fqdn": new_test_fqdn, "maintenance_mode": True},
            content_type=APPLICATION_JSON,
        )
        self.host.refresh_from_db()

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(self.host.fqdn, new_test_fqdn)

    def test_host_update_same_fqdn_success(self):
        self.host.state = "active"
        self.host.save(update_fields=["state"])

        response: Response = self.client.patch(
            path=reverse("host-details", kwargs={"host_id": self.host.pk}),
            data={"fqdn": self.host.fqdn, "maintenance_mode": True},
            content_type=APPLICATION_JSON,
        )

        self.assertEqual(response.status_code, HTTP_200_OK)

    def test_host_update_fqdn_not_created_state_fail(self):
        self.host.state = "active"
        self.host.save(update_fields=["state"])

        response: Response = self.client.patch(
            path=reverse("host-details", kwargs={"host_id": self.host.pk}),
            data={"fqdn": "new-test-fqdn", "maintenance_mode": True},
            content_type=APPLICATION_JSON,
        )

        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "HOST_UPDATE_ERROR")

    def test_host_update_fqdn_has_cluster_fail(self):
        self.host.state = "active"
        self.host.save(update_fields=["state"])

        cluster = Cluster.objects.create(
            prototype=Prototype.objects.create(bundle=Bundle.objects.first(), type="cluster"),
            name="test_cluster",
        )
        self.host.state = "active"
        self.host.cluster = cluster
        self.host.save(update_fields=["state", "cluster"])

        response: Response = self.client.patch(
            path=reverse("host-details", kwargs={"host_id": self.host.pk}),
            data={"fqdn": "new-test-fqdn", "maintenance_mode": True},
            content_type=APPLICATION_JSON,
        )

        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "HOST_UPDATE_ERROR")

    def test_host_update_wrong_fqdn_fail(self):
        response: Response = self.client.patch(
            path=reverse("host-details", kwargs={"host_id": self.host.pk}),
            data={"fqdn": ".new_test_fqdn"},
            content_type=APPLICATION_JSON,
        )

        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["code"], "WRONG_NAME")

    def test_host_update_not_created_state_wrong_fqdn_fail(self):
        self.host.state = "active"
        self.host.save(update_fields=["state"])

        response: Response = self.client.patch(
            path=reverse("host-details", kwargs={"host_id": self.host.pk}),
            data={"fqdn": ".new_test_fqdn"},
            content_type=APPLICATION_JSON,
        )

        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["code"], "WRONG_NAME")

    def test_host_create_duplicated_fqdn_fail(self):
        response = self.client.post(
            path=reverse("host"),
            data={
                "fqdn": self.host.fqdn,
                "provider_id": self.host.provider.pk,
                "prototype_id": self.host.prototype.pk,
            },
            content_type=APPLICATION_JSON,
        )

        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "HOST_CONFLICT")
        self.assertEqual(response.json()["desc"], "duplicate host")

    def test_host_update_duplicated_fqdn_fail(self):
        fqdn = "another"
        Host.objects.create(
            fqdn=fqdn,
            prototype=Prototype.objects.all()[0],
            provider=self.provider,
            maintenance_mode=False,
        )

        response = self.client.put(
            path=reverse("host-details", kwargs={"host_id": self.host.pk}),
            data={
                "fqdn": fqdn,
                "provider_id": self.host.provider.pk,
                "prototype_id": self.host.prototype.pk,
                "maintenance_mode": self.host.maintenance_mode,
            },
            content_type=APPLICATION_JSON,
        )
        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "HOST_CONFLICT")
        self.assertEqual(response.json()["desc"], "duplicate host")

        response = self.client.patch(
            path=reverse("host-details", kwargs={"host_id": self.host.pk}),
            data={
                "fqdn": fqdn,
                "provider_id": self.host.provider.pk,
                "prototype_id": self.host.prototype.pk,
                "maintenance_mode": self.host.maintenance_mode,
            },
            content_type=APPLICATION_JSON,
        )
        self.assertEqual(response.status_code, HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "HOST_CONFLICT")
        self.assertEqual(response.json()["desc"], "duplicate host")

    def test_host_create_fqdn_validation(self):
        url = reverse("host")
        amount_of_hosts = Host.objects.count()
        extra_payload = {
            "prototype_id": self.host.prototype.pk,
            "provider_id": self.host.provider.pk,
        }

        for value in self.incorrect_values:
            with self.subTest("invalid", fqdn=value):
                response = self.client.post(
                    path=url,
                    data={"fqdn": value, **extra_payload},
                    content_type=APPLICATION_JSON,
                )
                self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
                err = response.json()
                if "code" in err:
                    self.assertEqual(err["code"], "WRONG_NAME")
                else:
                    self.assertIn("fqdn", err)
                    self.assertEqual(
                        err["fqdn"], ["Ensure this field has no more than 253 characters."]
                    )
                self.assertEqual(Host.objects.count(), amount_of_hosts)

        for value in self.correct_values:
            with self.subTest("valid", fqdn=value):
                response = self.client.post(
                    path=url,
                    data={"fqdn": value, **extra_payload},
                    content_type=APPLICATION_JSON,
                )
                self.assertEqual(response.status_code, HTTP_201_CREATED)
                self.assertEqual(response.json()["fqdn"], value)

    def test_host_update_fqdn_validation(self):
        self.host.maintenance_mode = False
        self.host.save(update_fields=["maintenance_mode"])
        fqdn = self.host.fqdn
        default_values = {
            "provider_id": self.host.provider.pk,
            "prototype_id": self.host.prototype.pk,
            "maintenance_mode": self.host.maintenance_mode,
        }

        for value in self.incorrect_values:
            with self.subTest("incorrect-put", fqdn=value):
                response: Response = self.client.put(
                    path=reverse("host-details", kwargs={"host_id": self.host.pk}),
                    data={"fqdn": value, **default_values},
                    content_type=APPLICATION_JSON,
                )
                self.check_incorrect_fqdn_update(response, fqdn)

            with self.subTest("incorrect-patch", fqdn=value):
                response: Response = self.client.patch(
                    path=reverse("host-details", kwargs={"host_id": self.host.pk}),
                    data={"fqdn": value},
                    content_type=APPLICATION_JSON,
                )
                self.check_incorrect_fqdn_update(response, fqdn)

        for value in self.correct_values:
            with self.subTest("correct-put", fqdn=value):
                response: Response = self.client.put(
                    path=reverse("host-details", kwargs={"host_id": self.host.pk}),
                    data={"fqdn": value, **default_values},
                    content_type=APPLICATION_JSON,
                )
                self.check_success_fqdn_update(response, value)

            self.host.fqdn = fqdn
            self.host.save()
            with self.subTest("correct-patch", fqdn=value):
                response: Response = self.client.patch(
                    path=reverse("host-details", kwargs={"host_id": self.host.pk}),
                    data={"fqdn": value},
                    content_type=APPLICATION_JSON,
                )
                self.check_success_fqdn_update(response, value)

    def test_host_is_maintenance_mode_available(self):
        self.check_is_maintenance_mode_allowed(self.host, False)
        host_in_cluster_mm_allowed = self.create_host_in_cluster("mmallowed", True)
        self.check_is_maintenance_mode_allowed(host_in_cluster_mm_allowed, True)
        host_in_cluster_mm_not_allowed = self.create_host_in_cluster("mmnotallowed", False)
        self.check_is_maintenance_mode_allowed(host_in_cluster_mm_not_allowed, False)
