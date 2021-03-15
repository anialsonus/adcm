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
import json
import os
import random

import allure
import pytest
from adcm_pytest_plugin import utils
from adcm_pytest_plugin.docker_utils import DockerWrapper
from coreapi import exceptions
from jsonschema import validate


# pylint: disable=E0401, W0611, W0621
from tests.library import errorcodes, steps

BUNDLES = os.path.join(os.path.dirname(__file__), "../stack/")
SCHEMAS = os.path.join(os.path.dirname(__file__), "schemas/")


def test_load_host_provider(sdk_client_fs):
    sdk_client_fs.upload_from_fs(BUNDLES + "hostprovider_bundle")
    with allure.step("Check bundle list"):
        assert len(sdk_client_fs.bundle_list()) == 1


@pytest.mark.skip(reason="is not compatible with new adcm_client objects")
def test_validate_provider_prototype(client):
    steps.upload_bundle(client, BUNDLES + 'hostprovider_bundle')
    with allure.step('Load provider prototype'):
        provider_prototype = json.loads(json.dumps(client.stack.provider.list()[0]))
        schema = json.load(
            open(SCHEMAS + '/stack_list_item_schema.json')
        )
    with allure.step('Check provider prototype'):
        assert validate(provider_prototype, schema) is None


def test_should_create_provider_wo_description(sdk_client_fs):
    bundle = sdk_client_fs.upload_from_fs(BUNDLES + "hostprovider_bundle")
    bundle.provider_prototype().provider_create(name=utils.random_string())
    with allure.step("Check provider list"):
        assert len(sdk_client_fs.provider_list()) == 1


def test_should_create_provider_w_description(sdk_client_fs):
    bundle = sdk_client_fs.upload_from_fs(BUNDLES + "hostprovider_bundle")
    description = utils.random_string(140)
    provider = bundle.provider_prototype().provider_create(
        name=utils.random_string(),
        description=description)
    with allure.step("Check provider with description"):
        assert provider.description == description


def test_get_provider_config(sdk_client_fs):
    bundle = sdk_client_fs.upload_from_fs(BUNDLES + "hostprovider_bundle")
    provider = bundle.provider_prototype().provider_create(
        name=utils.random_string())
    with allure.step("Check provider config"):
        assert provider.config() is not None


@allure.link("https://jira.arenadata.io/browse/ADCM-472")
def test_provider_shouldnt_be_deleted_when_it_has_host(sdk_client_fs):
    bundle = sdk_client_fs.upload_from_fs(BUNDLES + "hostprovider_bundle")
    provider = bundle.provider_prototype().provider_create(name=utils.random_string())
    provider.host_create(fqdn=utils.random_string())
    with allure.step("Delete provider"):
        with pytest.raises(exceptions.ErrorMessage) as e:
            provider.delete()
    with allure.step("Check error"):
        errorcodes.PROVIDER_CONFLICT.equal(e, "There is host ", " of host provider ")


@pytest.mark.skip("is not compatible with new adcm_client objects")
def test_shouldnt_create_host_with_unknown_prototype(client):
    steps.upload_bundle(client, BUNDLES + 'hostprovider_bundle')
    with allure.step('Create host'):
        with pytest.raises(exceptions.ErrorMessage) as e:
            client.host.create(prototype_id=client.stack.host.list()[0]['id'],
                               provider_id=random.randint(100, 500),
                               fqdn=utils.random_string())
    with allure.step('Check error provider doesnt exist'):
        errorcodes.PROVIDER_NOT_FOUND.equal(e, "provider doesn't exist")
