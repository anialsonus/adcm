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
import random
import time

from adcm_pytest_plugin import utils
from adcm_pytest_plugin.docker_utils import get_file_from_container

# pylint: disable=W0611, W0621
from tests.library import steps


def random_proto(client, apiobject):
    if apiobject == 'cluster':
        return random.choice(client.stack.cluster.list())
    elif apiobject == 'service':
        return random.choice(client.stack.service.list())
    else:
        return random.choice(client.stack.host.list())


def prepare(client):
    cluster = client.cluster.create(prototype_id=random_proto(client, 'cluster')['id'],
                                    name='new_')
    client.cluster.service.create(cluster_id=cluster['id'],
                                  prototype_id=random_proto(client, 'service')['id'])
    return cluster


def test_check_inventories_file(adcm, client):
    bundledir = utils.get_data_dir(__file__, 'cluster_inventory_tests')
    steps.upload_bundle(client, bundledir)
    cluster = prepare(client)
    client.cluster.action.run.create(
        cluster_id=cluster['id'],
        action_id=random.choice(client.cluster.action.list(cluster_id=cluster['id']))['id'])
    time.sleep(5)
    text = get_file_from_container(adcm, '/adcm/data/run/1/', 'inventory.json')
    inventory = json.loads(text.read().decode('utf8'))
    template = open(utils.get_data_dir(__file__, 'cluster-inventory.json'), 'rb')
    expected = json.loads(template.read().decode('utf8'))
    assert inventory == expected
