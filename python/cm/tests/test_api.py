#!/usr/bin/env python3
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

# Since this module is beyond QA responsibility we will not fix docstrings here
# pylint: disable=missing-function-docstring, missing-class-docstring

"""Unit-like API tests"""

import json
import os
import string
from uuid import uuid4

from django.conf import settings
from django.db import transaction
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

import requests

from init_db import init as init_adcm
from rbac.upgrade.role import init_roles


class TestBase(TestCase):
    files_dir = os.path.join(settings.BASE_DIR, 'python', 'cm', 'tests', 'files')

    token = None
    url = None
    debug = os.environ.get('BASE_DEBUG', False)

    def setUp(self) -> None:
        init_adcm()
        init_roles()

        self.client = APIClient(HTTP_USER_AGENT='Mozilla/5.0')
        res = self.client.post(
            path=reverse("rbac:token"),
            data={"username": "admin", "password": "admin"},
            format="json",
        )
        self.client.defaults["Authorization"] = f"Token {res.data['token']}"

        self.client_unauthorized = APIClient(HTTP_USER_AGENT='Mozilla/5.0')

        self.bundle_adh_name = 'adh.1.5.tar'
        self.bundle_ssh_name = 'ssh.1.0.tar'

    def api(self, path, res, data=''):
        self.print_result(path, res, data)
        return res

    @property
    def token_hdr(self):
        return {'Authorization': 'Token ' + self.token}

    def api_get(self, path):
        # return self.client.get(path, content_type="application/json").json()
        return self.api(path, requests.get(self.url + path, headers=self.token_hdr))

    def api_delete(self, path):
        # return self.client.delete(path, content_type="application/json").json()
        return self.api(path, requests.delete(self.url + path, headers=self.token_hdr))

    def api_post(self, path, data):
        # return self.client.post(path, data=data, content_type="application/json").json()
        return self.api(
            path,
            requests.post(
                self.url + path,
                data=json.dumps(data),
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': 'Token ' + self.token,
                },
            ),
            data,
        )

    def api_put(self, path, data):
        # return self.client.put(path, data=data, content_type="application/json").json()
        return self.api(
            path,
            requests.put(
                self.url + path,
                data=json.dumps(data),
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': 'Token ' + self.token,
                },
            ),
            data,
        )

    def api_patch(self, path, data):
        # return self.client.patch(path, data=data, content_type="application/json").json()
        return self.api(
            path,
            requests.patch(
                self.url + path,
                data=json.dumps(data),
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': 'Token ' + self.token,
                },
            ),
            data,
        )

    def print_result(self, path, response, data=''):
        if self.debug:
            print(f"IN:  {path}")
            if data:
                print(f"DATA:{data}")
            print(f"OUT: {response.status_code} {response.text}")
            # print("HDR: {}".format(r.headers))
            print("")

    def load_bundle(self, bundle_name):
        with open(os.path.join(self.files_dir, bundle_name), encoding="utf-8") as f:
            with transaction.atomic():
                response = self.client.post(
                    path=reverse("upload-bundle"),
                    data={"file": f},
                )
            self.assertEqual(response.status_code, 201, msg=response.content)
        with transaction.atomic():
            response = self.client.post(
                path=reverse("load-bundle"),
                data={"bundle_file": bundle_name},
            )
        self.assertEqual(response.status_code, 200, msg=response.content)


class TestAPI(TestBase):  # pylint: disable=too-many-public-methods
    token = None
    url = 'http://localhost:8000/api/v1'
    cluster = 'adh42'
    host = 'test.host.net'
    service = 'ZOOKEEPER'
    service_id = 1
    component = 'ZOOKEEPER_SERVER'
    adh_bundle = 'adh.1.5.tar'
    ssh_bundle = 'ssh.1.0.tar'

    def get_service_proto_id(self):
        response = self.client.get(reverse('service-type'))
        self.assertEqual(response.status_code, 200, msg=response.content)
        for service in response.json():
            if service['name'] == self.service:
                return service['id']
        return 0

    def get_action_id(self, service_id, action_name):
        response = self.api_get(
            '/stack/service/' + str(service_id) + '/action/'
        )  # reverse('service-actions', kwargs={'prototype_id': 1})
        self.assertEqual(response.status_code, 200, msg=response.text)
        for action in response.json():
            if action['name'] == action_name:
                return action['id']
        return 0

    def get_component_id(self, cluster_id, service_id, component_name):
        response = self.api_get(f'/cluster/{cluster_id}/service/{service_id}/component/')
        self.assertEqual(response.status_code, 200, msg=response.text)
        for comp in response.json():
            if comp['name'] == component_name:
                return comp['id']
        return 0

    def get_cluster_proto_id(self):
        response = self.client.get(reverse('cluster-type'))
        self.assertEqual(response.status_code, 200, msg=response.content)
        for cluster in response.json():
            return cluster['bundle_id'], cluster['id']

    def get_host_proto_id(self):
        response = self.client.get(reverse('host-type'))
        self.assertEqual(response.status_code, 200, msg=response.content)
        for host in response.json():
            return (host['bundle_id'], host['id'])

    def get_host_provider_proto_id(self):
        response = self.client.get(reverse('provider-type'))
        self.assertEqual(response.status_code, 200, msg=response.content)
        for provider in response.json():
            return (provider['bundle_id'], provider['id'])

    def create_host(self, fqdn, name=None):
        name = name or uuid4().hex
        ssh_bundle_id, host_proto = self.get_host_proto_id()
        _, provider_proto = self.get_host_provider_proto_id()
        response = self.client.post(
            reverse('provider'), {'name': name, 'prototype_id': provider_proto}
        )
        self.assertEqual(response.status_code, 201, msg=response.content)
        provider_id = response.json()['id']
        response = self.client.post(
            reverse('host'), {'fqdn': fqdn, 'prototype_id': host_proto, 'provider_id': provider_id}
        )
        self.assertEqual(response.status_code, 201, msg=response.content)
        host_id = response.json()['id']
        return (ssh_bundle_id, provider_id, host_id)

    def test_access(self):
        api = [reverse('cluster'), reverse('host'), reverse('job'), reverse('task')]
        for url in api:
            response = self.client_unauthorized.get(url)
            self.assertEqual(response.status_code, 401, msg=response.content)
            self.assertEqual(
                response.json()['detail'], 'Authentication credentials were not provided.'
            )

        for url in api:
            response = self.client_unauthorized.post(url, data={})
            self.assertEqual(response.status_code, 401, msg=response.content)
            self.assertEqual(
                response.json()['detail'], 'Authentication credentials were not provided.'
            )

        for url in api:
            response = self.client_unauthorized.put(url, {})
            self.assertEqual(response.status_code, 401, msg=response.content)
            self.assertEqual(
                response.json()['detail'], 'Authentication credentials were not provided.'
            )

        for url in api:
            response = self.client_unauthorized.delete(url)
            self.assertEqual(response.status_code, 401, msg=response.content)
            self.assertEqual(
                response.json()['detail'], 'Authentication credentials were not provided.'
            )

    def test_schema(self):
        response = self.client.get('/api/v1/schema/')
        self.assertEqual(response.status_code, 200, msg=response.content)

    def test_docs(self):
        response = self.client.get('/api/v1/docs/')
        self.assertEqual(response.status_code, 200, msg=response.content)
        response = self.client.get('/api/v1/docs/md/')
        self.assertEqual(response.status_code, 200, msg=response.content)

    def test_cluster(self):  # pylint: disable=too-many-statements
        cluster_name = 'test_cluster'
        cluster_url = reverse('cluster')
        # response = self.api_post('/stack/load/', {'bundle_file': self.adh_bundle})
        # self.assertEqual(response.status_code, 200, msg=response.text)
        self.load_bundle(self.bundle_adh_name)
        bundle_id, proto_id = self.get_cluster_proto_id()

        response = self.client.post(cluster_url, {})
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['name'], ['This field is required.'])

        response = self.client.post(cluster_url, {'name': ''})
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['name'], ['This field may not be blank.'])

        response = self.client.post(cluster_url, {'name': cluster_name})
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['prototype_id'], ['This field is required.'])

        response = self.client.post(cluster_url, {'name': cluster_name, 'prototype_id': ''})
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['prototype_id'], ['A valid integer is required.'])

        response = self.client.post(
            cluster_url, {'name': cluster_name, 'prototype_id': 'some-string'}
        )
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['prototype_id'], ['A valid integer is required.'])

        response = self.client.post(cluster_url, {'name': cluster_name, 'prototype_id': 100500})
        self.assertEqual(response.status_code, 404, msg=response.content)
        self.assertEqual(response.json()['code'], 'PROTOTYPE_NOT_FOUND')

        response = self.client.post(
            cluster_url,
            {'name': cluster_name, 'prototype_id': proto_id, 'description': ''},
            format='json',
        )
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['description'], ['This field may not be blank.'])

        response = self.client.post(cluster_url, {'name': cluster_name, 'prototype_id': proto_id})
        self.assertEqual(response.status_code, 201, msg=response.content)

        cluster_id = response.json()['id']
        this_cluster_url = reverse('cluster-details', kwargs={'cluster_id': cluster_id})

        response = self.client.get(this_cluster_url)
        self.assertEqual(response.status_code, 200, msg=response.content)
        self.assertEqual(response.json()['name'], cluster_name)

        response = self.client.post(cluster_url, {'name': cluster_name, 'prototype_id': proto_id})
        self.assertEqual(response.status_code, 409, msg=response.content)
        self.assertEqual(response.json()['code'], 'CLUSTER_CONFLICT')

        response = self.client.put(this_cluster_url, {})
        self.assertEqual(response.status_code, 405, msg=response.content)
        self.assertEqual(response.json()['detail'], 'Method "PUT" not allowed.')

        response = self.client.delete(this_cluster_url)
        self.assertEqual(response.status_code, 204, msg=response.content)

        response = self.client.get(this_cluster_url)
        self.assertEqual(response.status_code, 404, msg=response.content)
        self.assertEqual(response.json()['code'], 'CLUSTER_NOT_FOUND')

        response = self.client.delete(this_cluster_url)
        self.assertEqual(response.status_code, 404, msg=response.content)
        self.assertEqual(response.json()['code'], 'CLUSTER_NOT_FOUND')

        response = self.client.delete(reverse('bundle-details', kwargs={'bundle_id': bundle_id}))
        self.assertEqual(response.status_code, 204, msg=response.content)

    def test_cluster_patching(self):
        name = 'test_cluster'
        cluster_url = reverse('cluster')

        self.load_bundle(self.bundle_adh_name)
        bundle_id, proto_id = self.get_cluster_proto_id()

        with transaction.atomic():
            response = self.client.post(cluster_url, {'name': name, 'prototype_id': proto_id})
        self.assertEqual(response.status_code, 201, msg=response.content)

        cluster_id = response.json()['id']
        first_cluster_url = reverse('cluster-details', kwargs={'cluster_id': cluster_id})

        patched_name = 'patched_cluster'
        with transaction.atomic():
            response = self.client.patch(first_cluster_url, {'name': patched_name}, format="json")
        self.assertEqual(response.status_code, 200, msg=response.content)
        self.assertEqual(response.json()['name'], patched_name)

        description = 'cluster_description'
        with transaction.atomic():
            response = self.client.patch(
                first_cluster_url, {'name': patched_name, 'description': description}, format="json"
            )
        self.assertEqual(response.status_code, 200, msg=response.content)
        self.assertEqual(response.json()['description'], description)

        with transaction.atomic():
            response = self.client.post(cluster_url, {'name': name, 'prototype_id': proto_id})
        self.assertEqual(response.status_code, 201, msg=response.content)

        second_cluster_id = response.json()['id']
        second_cluster_url = reverse('cluster-details', kwargs={'cluster_id': second_cluster_id})

        with transaction.atomic():
            response = self.client.patch(second_cluster_url, {'name': patched_name}, format="json")
        self.assertEqual(response.status_code, 409, msg=response.content)
        self.assertEqual(response.json()['code'], 'CLUSTER_CONFLICT')

        with transaction.atomic():
            response = self.client.delete(first_cluster_url)
        self.assertEqual(response.status_code, 204, msg=response.content)

        with transaction.atomic():
            response = self.client.delete(second_cluster_url)
        self.assertEqual(response.status_code, 204, msg=response.content)

        with transaction.atomic():
            response = self.client.delete(
                reverse('bundle-details', kwargs={'bundle_id': bundle_id})
            )
        self.assertEqual(response.status_code, 204, msg=response.content)

    def test_host(self):  # pylint: disable=too-many-statements
        host = 'test.server.net'
        host_url = reverse('host')

        self.load_bundle(self.bundle_ssh_name)
        ssh_bundle_id, host_proto = self.get_host_proto_id()

        response = self.client.post(host_url, {})
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['fqdn'], ['This field is required.'])

        response = self.client.post(
            host_url, {'fqdn': host, 'prototype_id': host_proto, 'provider_id': 0}
        )
        self.assertEqual(response.status_code, 404, msg=response.content)
        self.assertEqual(response.json()['code'], 'PROVIDER_NOT_FOUND')

        _, provider_proto = self.get_host_provider_proto_id()
        response = self.client.post(
            reverse('provider'), {'name': 'DF1', 'prototype_id': provider_proto}
        )
        self.assertEqual(response.status_code, 201, msg=response.content)
        provider_id = response.json()['id']

        response = self.client.post(
            host_url, {'fqdn': host, 'prototype_id': 42, 'provider_id': provider_id}
        )
        self.assertEqual(response.status_code, 404, msg=response.content)
        self.assertEqual(response.json()['code'], 'PROTOTYPE_NOT_FOUND')

        response = self.client.post(host_url, {'fqdn': host, 'provider_id': provider_id})
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['prototype_id'], ['This field is required.'])

        response = self.client.post(host_url, {'fqdn': host, 'prototype_id': host_proto})
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['provider_id'], ['This field is required.'])

        response = self.client.post(
            host_url,
            {
                'fqdn': 'x' + 'deadbeef' * 32,  # 257 chars
                'prototype_id': host_proto,
                'provider_id': provider_id,
            },
        )
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['desc'], 'Host name is too long. Max length is 256')

        response = self.client.post(
            host_url,
            {
                'fqdn': 'x' + string.punctuation,
                'prototype_id': host_proto,
                'provider_id': provider_id,
            },
        )
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['code'], 'WRONG_NAME')

        response = self.client.post(
            host_url, {'fqdn': host, 'prototype_id': host_proto, 'provider_id': provider_id}
        )
        self.assertEqual(response.status_code, 201, msg=response.content)
        host_id = response.json()['id']

        this_host_url = reverse('host-details', kwargs={'host_id': host_id})

        response = self.client.get(this_host_url)
        self.assertEqual(response.status_code, 200, msg=response.content)
        self.assertEqual(response.json()['fqdn'], host)

        response = self.client.put(this_host_url, {}, content_type="application/json")
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(
            response.json(),
            {
                'prototype_id': ['This field is required.'],
                'provider_id': ['This field is required.'],
                'fqdn': ['This field is required.'],
                'maintenance_mode': ['This field is required.'],
            },
        )

        response = self.client.post(
            host_url, {'fqdn': host, 'prototype_id': host_proto, 'provider_id': provider_id}
        )
        self.assertEqual(response.status_code, 409, msg=response.content)
        self.assertEqual(response.json()['code'], 'HOST_CONFLICT')

        response = self.client.delete(this_host_url)
        self.assertEqual(response.status_code, 204, msg=response.content)

        response = self.client.get(this_host_url)
        self.assertEqual(response.status_code, 404, msg=response.content)
        self.assertEqual(response.json()['code'], 'HOST_NOT_FOUND')

        response = self.client.delete(this_host_url)
        self.assertEqual(response.status_code, 404, msg=response.content)
        self.assertEqual(response.json()['code'], 'HOST_NOT_FOUND')

        response = self.client.delete(
            reverse('bundle-details', kwargs={'bundle_id': ssh_bundle_id})
        )
        self.assertEqual(response.status_code, 409, msg=response.content)
        self.assertEqual(response.json()['code'], 'BUNDLE_CONFLICT')

        response = self.client.delete(
            reverse('provider-details', kwargs={'provider_id': provider_id})
        )
        self.assertEqual(response.status_code, 204, msg=response.content)

        response = self.client.delete(
            reverse('bundle-details', kwargs={'bundle_id': ssh_bundle_id})
        )
        self.assertEqual(response.status_code, 204, msg=response.content)

    def test_cluster_host(self):
        host = 'test.host.net'
        cluster_url = reverse('cluster')

        self.load_bundle(self.bundle_adh_name)
        self.load_bundle(self.bundle_ssh_name)

        adh_bundle_id, cluster_proto = self.get_cluster_proto_id()

        response = self.client.post(
            cluster_url, {'name': self.cluster, 'prototype_id': cluster_proto}
        )
        cluster_id = response.json()['id']
        this_cluster_host_url = reverse('host', kwargs={'cluster_id': cluster_id})

        ssh_bundle_id, _, host_id = self.create_host(host)

        response = self.client.post(this_cluster_host_url, {})
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['host_id'], ['This field is required.'])

        response = self.client.post(this_cluster_host_url, {'host_id': 100500})
        self.assertEqual(response.status_code, 404, msg=response.content)
        self.assertEqual(response.json()['code'], 'HOST_NOT_FOUND')

        response = self.client.post(this_cluster_host_url, {'host_id': host_id})
        self.assertEqual(response.status_code, 201, msg=response.content)
        self.assertEqual(response.json()['id'], host_id)
        self.assertEqual(response.json()['cluster_id'], cluster_id)

        response = self.client.post(cluster_url, {'name': 'qwe', 'prototype_id': cluster_proto})
        cluster_id2 = response.json()['id']
        second_cluster_host_url = reverse('host', kwargs={'cluster_id': cluster_id2})

        response = self.client.post(second_cluster_host_url, {'host_id': host_id})
        self.assertEqual(response.status_code, 409, msg=response.content)
        self.assertEqual(response.json()['code'], 'FOREIGN_HOST')

        response = self.client.post(this_cluster_host_url, {'host_id': host_id})
        self.assertEqual(response.status_code, 409, msg=response.content)
        self.assertEqual(response.json()['code'], 'HOST_CONFLICT')

        response = self.client.delete(this_cluster_host_url + str(host_id) + '/')
        self.assertEqual(response.status_code, 204, msg=response.content)

        response = self.client.post(second_cluster_host_url, {'host_id': host_id})
        self.assertEqual(response.status_code, 201, msg=response.content)
        self.assertEqual(response.json()['cluster_id'], cluster_id2)

        self.client.delete(reverse('cluster-details', kwargs={'cluster_id': cluster_id}))
        self.client.delete(reverse('cluster-details', kwargs={'cluster_id': cluster_id2}))
        self.client.delete(reverse('host-details', kwargs={'host_id': host_id}))
        response = self.client.delete(
            reverse('bundle-details', kwargs={'bundle_id': adh_bundle_id})
        )
        self.assertEqual(response.status_code, 204, msg=response.content)
        response = self.client.delete(
            reverse('bundle-details', kwargs={'bundle_id': ssh_bundle_id})
        )
        self.assertEqual(response.status_code, 409, msg=response.content)
        self.assertEqual(response.json()['code'], 'BUNDLE_CONFLICT')

    def test_service(self):
        self.load_bundle(self.bundle_adh_name)
        service_id = self.get_service_proto_id()
        service_url = reverse('service-type')
        this_service_url = reverse('service-type-details', kwargs={'prototype_id': service_id})

        response = self.client.post(service_url, {})
        self.assertEqual(response.status_code, 405, msg=response.content)

        response = self.client.get(this_service_url)
        self.assertEqual(response.status_code, 200, msg=response.content)

        response = self.client.put(this_service_url, {}, content_type="application/json")
        self.assertEqual(response.status_code, 405, msg=response.content)

        response = self.client.delete(this_service_url)
        self.assertEqual(response.status_code, 405, msg=response.content)

        response = self.client.get(this_service_url)
        self.assertEqual(response.status_code, 200, msg=response.content)
        bundle_id = response.json()['bundle_id']

        response = self.client.delete(reverse('bundle-details', kwargs={'bundle_id': bundle_id}))
        self.assertEqual(response.status_code, 204, msg=response.content)

    def test_cluster_service(self):
        self.load_bundle(self.bundle_adh_name)

        service_proto_id = self.get_service_proto_id()
        bundle_id, cluster_proto_id = self.get_cluster_proto_id()

        cluster = 'test_cluster'
        cluster_url = reverse('cluster')
        response = self.client.post(
            cluster_url, {'name': cluster, 'prototype_id': cluster_proto_id}
        )
        self.assertEqual(response.status_code, 201, msg=response.content)
        cluster_id = response.json()['id']
        this_service_url = reverse('service', kwargs={'cluster_id': cluster_id})

        response = self.client.post(
            this_service_url,
            {'prototype_id': 'some-string'},
        )
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['prototype_id'], ['A valid integer is required.'])

        response = self.client.post(
            this_service_url,
            {
                'prototype_id': -service_proto_id,
            },
        )
        self.assertEqual(response.status_code, 404, msg=response.content)
        self.assertEqual(response.json()['code'], 'PROTOTYPE_NOT_FOUND')

        response = self.client.post(
            this_service_url,
            {
                'prototype_id': service_proto_id,
            },
        )
        self.assertEqual(response.status_code, 201, msg=response.content)
        service_id = response.json()['id']

        response = self.client.post(
            this_service_url,
            {
                'prototype_id': service_proto_id,
            },
        )
        self.assertEqual(response.status_code, 409, msg=response.content)
        self.assertEqual(response.json()['code'], 'SERVICE_CONFLICT')

        this_service_from_cluster_url = reverse(
            'service-details', kwargs={'cluster_id': cluster_id, 'service_id': service_id}
        )
        response = self.client.delete(this_service_from_cluster_url)
        self.assertEqual(response.status_code, 204, msg=response.content)

        response = self.client.delete(reverse('cluster-details', kwargs={'cluster_id': cluster_id}))
        self.assertEqual(response.status_code, 204, msg=response.content)

        response = self.client.delete(reverse('bundle-details', kwargs={'bundle_id': bundle_id}))
        self.assertEqual(response.status_code, 204, msg=response.content)

    # TODO: unskip
    def SKIP_test_hostcomponent(self):  # pylint: disable=too-many-statements,too-many-locals
        response = self.api_post('/stack/load/', {'bundle_file': self.adh_bundle})
        self.assertEqual(response.status_code, 200, msg=response.text)
        response = self.api_post('/stack/load/', {'bundle_file': self.ssh_bundle})
        self.assertEqual(response.status_code, 200, msg=response.text)

        adh_bundle_id, cluster_proto = self.get_cluster_proto_id()
        ssh_bundle_id, _, host_id = self.create_host(self.host)
        service_proto_id = self.get_service_proto_id()
        response = self.api_post('/cluster/', {'name': self.cluster, 'prototype_id': cluster_proto})
        cluster_id = response.json()['id']

        response = self.api_post(
            '/cluster/' + str(cluster_id) + '/service/', {'prototype_id': service_proto_id}
        )
        self.assertEqual(response.status_code, 201, msg=response.text)
        service_id = response.json()['id']

        hc_url = '/cluster/' + str(cluster_id) + '/hostcomponent/'
        response = self.api_post(hc_url, {'hc': {}})
        self.assertEqual(response.status_code, 400, msg=response.text)
        self.assertEqual(response.json()['code'], "INVALID_INPUT")
        self.assertEqual(response.json()['desc'], "hc field is required")

        comp_id = self.get_component_id(cluster_id, service_id, self.component)
        response = self.api_post(
            # TODO: figure out how to pass "hc" param in client's data
            hc_url,
            {'hc': [{'service_id': service_id, 'host_id': 100500, 'component_id': comp_id}]},
        )
        self.assertEqual(response.status_code, 404, msg=response.text)
        self.assertEqual(response.json()['code'], "HOST_NOT_FOUND")

        response = self.api_post(
            hc_url, {'hc': [{'service_id': service_id, 'host_id': host_id, 'component_id': 100500}]}
        )
        self.assertEqual(response.status_code, 404, msg=response.text)
        self.assertEqual(response.json()['code'], "COMPONENT_NOT_FOUND")

        response = self.api_post(
            hc_url,
            {'hc': [{'service_id': service_id, 'host_id': host_id, 'component_id': comp_id}]},
        )
        self.assertEqual(response.status_code, 409, msg=response.text)
        self.assertEqual(response.json()['code'], "FOREIGN_HOST")

        response = self.api_post('/cluster/' + str(cluster_id) + '/host/', {'host_id': host_id})
        self.assertEqual(response.status_code, 201, msg=response.text)

        response = self.api_post(hc_url, {'hc': {'host_id': host_id, 'component_id': comp_id}})
        self.assertEqual(response.status_code, 400, msg=response.text)
        self.assertEqual(response.json()['code'], "INVALID_INPUT")
        self.assertEqual(response.json()['desc'], "hc field should be a list")

        response = self.api_post(hc_url, {'hc': [{'component_id': comp_id}]})
        self.assertEqual(response.status_code, 400, msg=response.text)
        self.assertEqual(response.json()['code'], "INVALID_INPUT")

        response = self.api_post(hc_url, {'hc': [{'host_id': host_id}]})
        self.assertEqual(response.status_code, 400, msg=response.text)
        self.assertEqual(response.json()['code'], "INVALID_INPUT")

        response = self.api_post(
            hc_url,
            {
                'hc': [
                    {'service_id': service_id, 'host_id': 1, 'component_id': comp_id},
                    {'service_id': service_id, 'host_id': 1, 'component_id': comp_id},
                ]
            },
        )
        self.assertEqual(response.status_code, 400, msg=response.text)
        self.assertEqual(response.json()['code'], "INVALID_INPUT")
        self.assertEqual(response.json()['desc'][0:9], "duplicate")

        response = self.api_post(
            hc_url,
            {'hc': [{'service_id': service_id, 'host_id': host_id, 'component_id': comp_id}]},
        )
        self.assertEqual(response.status_code, 201, msg=response.text)
        hs_id = response.json()[0]['id']

        response = self.api_get(hc_url + str(hs_id) + '/')
        self.assertEqual(response.status_code, 200, msg=response.text)

        zclient_id = self.get_component_id(cluster_id, service_id, 'ZOOKEEPER_CLIENT')
        response = self.api_post(
            hc_url,
            {'hc': [{'service_id': service_id, 'host_id': host_id, 'component_id': zclient_id}]},
        )
        self.assertEqual(response.status_code, 201, msg=response.text)

        response = self.api_post('/cluster/', {'name': 'qwe', 'prototype_id': cluster_proto})
        cluster_id2 = response.json()['id']

        response = self.api_post(
            '/cluster/' + str(cluster_id2) + '/hostcomponent/',
            {'hc': [{'service_id': service_id, 'host_id': host_id, 'component_id': comp_id}]},
        )
        self.assertEqual(response.status_code, 404, msg=response.text)
        self.assertEqual(response.json()['code'], "CLUSTER_SERVICE_NOT_FOUND")

        response = self.api_post(
            '/cluster/' + str(cluster_id2) + '/service/', {'prototype_id': service_proto_id}
        )
        service_id2 = response.json()['id']
        self.assertEqual(response.status_code, 201, msg=response.text)
        comp_id2 = self.get_component_id(cluster_id2, service_id2, self.component)
        response = self.api_post(
            '/cluster/' + str(cluster_id2) + '/hostcomponent/',
            {'hc': [{'service_id': service_id2, 'host_id': host_id, 'component_id': comp_id2}]},
        )
        self.assertEqual(response.status_code, 409, msg=response.text)
        self.assertEqual(response.json()['code'], "FOREIGN_HOST")

        response = self.api_delete(hc_url + str(hs_id) + '/')
        self.assertEqual(response.status_code, 405, msg=response.text)

        self.api_delete('/cluster/' + str(cluster_id) + '/')
        self.api_delete('/cluster/' + str(cluster_id2) + '/')
        self.api_delete('/host/' + str(host_id) + '/')
        response = self.api_delete('/stack/bundle/' + str(adh_bundle_id) + '/')
        self.assertEqual(response.status_code, 204, msg=response.text)
        response = self.api_delete('/stack/bundle/' + str(ssh_bundle_id) + '/')
        self.assertEqual(response.status_code, 204, msg=response.text)

    # def test_task(self):
    #     response = self.api_post('/stack/load/', {'bundle_file': self.adh_bundle})
    #     self.assertEqual(response.status_code, 200, msg=response.text)
    #     response = self.api_post('/stack/load/', {'bundle_file': self.ssh_bundle})
    #     self.assertEqual(response.status_code, 200, msg=response.text)
    #
    #     ssh_bundle_id, provider_id, host_id = self.create_host(self.host)
    #     config = {'config': {'entry': 'some value'}}
    #     response = self.api_post(f'/provider/{provider_id}/config/history/', config)
    #     self.assertEqual(response.status_code, 201, msg=response.text)
    #
    #     adh_bundle_id, cluster_proto = self.get_cluster_proto_id()
    #     service_id = self.get_service_proto_id()
    #     action_id = self.get_action_id(service_id, 'start')
    #     response = self.api_post('/cluster/', {'name': self.cluster, 'prototype_id': cluster_proto})
    #     cluster_id = response.json()['id']
    #
    #     response = self.api_post(f'/cluster/{cluster_id}/host/', {'host_id': host_id})
    #     self.assertEqual(response.status_code, 201, msg=response.text)
    #
    #     response = self.api_post(f'/cluster/{cluster_id}/service/', {'prototype_id': service_id})
    #     self.assertEqual(response.status_code, 201, msg=response.text)
    #     service_id = response.json()['id']
    #
    #     comp_id = self.get_component_id(cluster_id, service_id, self.component)
    #     response = self.api_post(
    #         f'/cluster/{cluster_id}/hostcomponent/',
    #         {'hc': [{'service_id': service_id, 'host_id': host_id, 'component_id': comp_id}]},
    #     )
    #     self.assertEqual(response.status_code, 201, msg=response.text)
    #
    #     response = self.api_post(f'/cluster/{cluster_id}/action/{action_id}/run/', {})
    #     self.assertEqual(response.status_code, 409, msg=response.text)
    #     self.assertEqual(response.json()['code'], 'TASK_ERROR')
    #     self.assertEqual(response.json()['desc'], 'object has issues')
    #
    #     response = self.api_post(f'/cluster/{cluster_id}/config/history/', {'config': {'required': 42}})
    #     self.assertEqual(response.status_code, 201, msg=response.text)
    #
    #     response = self.api_post(f'/cluster/{cluster_id}/action/{action_id}/run/', {})
    #     self.assertEqual(response.status_code, 201, msg=response.text)
    #     task_id = response.json()['id']
    #     job_id = task_id
    #
    #     response = self.api_get('/task/' + str(task_id) + '/')
    #     self.assertEqual(response.status_code, 200, msg=response.text)
    #
    #     response = self.api_get('/job/' + str(job_id) + '/')
    #     self.assertEqual(response.status_code, 200, msg=response.text)
    #
    #     response = self.api_delete('/job/' + str(job_id) + '/')
    #     self.assertEqual(response.status_code, 405, msg=response.text)
    #
    #     response = self.api_get('/job/' + str(job_id) + '/log/' + str(3))
    #     self.assertEqual(response.status_code, 404, msg=response.text)
    #     self.assertEqual(response.json()['code'], 'LOG_NOT_FOUND')
    #
    #     time.sleep(2)
    #     self.api_delete('/cluster/' + str(cluster_id) + '/')
    #     self.api_delete('/host/' + str(host_id) + '/')
    #     response = self.api_delete('/stack/bundle/' + str(adh_bundle_id) + '/')
    #     response = self.api_delete('/stack/bundle/' + str(ssh_bundle_id) + '/')

    def test_config(self):  # pylint: disable=too-many-statements
        self.load_bundle(self.bundle_adh_name)
        adh_bundle_id, proto_id = self.get_cluster_proto_id()
        service_proto_id = self.get_service_proto_id()
        response = self.client.post(
            reverse('cluster'), {'name': self.cluster, 'prototype_id': proto_id}
        )
        cluster_id = response.json()['id']

        response = self.client.get(reverse('service', kwargs={'cluster_id': cluster_id}))
        self.assertEqual(response.status_code, 200, msg=response.content)
        self.assertEqual(response.json(), [])

        response = self.client.post(
            reverse('service', kwargs={'cluster_id': cluster_id}), {'prototype_id': 100500}
        )
        self.assertEqual(response.status_code, 404, msg=response.content)
        self.assertEqual(response.json()['code'], 'PROTOTYPE_NOT_FOUND')

        response = self.client.post(
            reverse('service', kwargs={'cluster_id': cluster_id}),
            {'prototype_id': service_proto_id},
        )
        self.assertEqual(response.status_code, 201, msg=response.content)
        service_id = response.json()['id']

        zurl = reverse(
            'service-details', kwargs={'cluster_id': cluster_id, 'service_id': service_id}
        )
        response = self.client.get(zurl)
        self.assertEqual(response.status_code, 200, msg=response.content)

        response = self.client.get(
            reverse(
                'config-current',
                kwargs={
                    'cluster_id': cluster_id,
                    'service_id': service_id,
                    'object_type': 'service',
                    'version': 'current',
                },
            )
        )
        self.assertEqual(response.status_code, 200, msg=response.content)
        id1 = response.json()['id']
        config = response.json()['config']
        self.assertEqual(config['zoo.cfg']['autopurge.purgeInterval'], 24)

        config_history_url = reverse(
            'config-history',
            kwargs={'cluster_id': cluster_id, 'service_id': service_id, 'object_type': 'service'},
        )
        response = self.client.post(config_history_url, {'config': 'qwe'})
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['config'], ['Value must be valid JSON.'])

        response = self.client.post(config_history_url, {'config': 42})
        self.assertEqual(response.status_code, 400, msg=response.content)
        self.assertEqual(response.json()['desc'], "config should not be just one int or float")

        config['zoo.cfg']['autopurge.purgeInterval'] = 42
        config['zoo.cfg']['port'] = 80
        response = self.client.post(config_history_url, {'config': config}, format='json')
        self.assertEqual(response.status_code, 201, msg=response.content)
        id2 = response.json()['id']

        response = self.client.get(
            reverse(
                'config-history-version',
                kwargs={
                    'cluster_id': cluster_id,
                    'service_id': service_id,
                    'object_type': 'service',
                    'version': id2,
                },
            )
        )
        self.assertEqual(response.status_code, 200, msg=response.content)
        config = response.json()['config']
        self.assertEqual(config['zoo.cfg']['autopurge.purgeInterval'], 42)

        response = self.client.patch(
            reverse(
                'config-history-version-restore',
                kwargs={
                    'cluster_id': cluster_id,
                    'service_id': service_id,
                    'object_type': 'service',
                    'version': id1,
                },
            ),
            {'description': 'New config'},
            format="json",
        )
        self.assertEqual(response.status_code, 200, msg=response.content)
        response = self.client.get(
            reverse(
                'config-current',
                kwargs={
                    'cluster_id': cluster_id,
                    'service_id': service_id,
                    'object_type': 'service',
                    'version': 'current',
                },
            )
        )
        config = response.json()['config']
        self.assertEqual(config['zoo.cfg']['autopurge.purgeInterval'], 24)

        response = self.client.get(
            reverse(
                'config-previous',
                kwargs={
                    'cluster_id': cluster_id,
                    'service_id': service_id,
                    'object_type': 'service',
                    'version': 'previous',
                },
            )
        )
        self.assertEqual(response.status_code, 200, msg=response.content)
        config = response.json()['config']
        self.assertEqual(config['zoo.cfg']['autopurge.purgeInterval'], 42)

        response = self.client.get(config_history_url)
        self.assertEqual(response.status_code, 200, msg=response.content)
        self.assertEqual(len(response.json()), 2)

        self.client.delete(reverse('cluster-details', kwargs={'cluster_id': cluster_id}))
        self.client.delete(reverse('bundle-details', kwargs={'bundle_id': adh_bundle_id}))
