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

from django.test import TestCase

from cm.unit_tests import utils


plausible_action_variants = {
    'unlimited': {
        'state_available': 'any',
        'state_unavailable': [],
        'multi_state_available': 'any',
        'multi_state_unavailable': [],
    },
    'limited_by_available_state': {
        'state_available': ['bimbo'],
        'state_unavailable': [],
        'multi_state_available': 'any',
        'multi_state_unavailable': [],
    },
    'limited_by_unavailable_state': {
        'state_available': 'any',
        'state_unavailable': ['bimbo'],
        'multi_state_available': 'any',
        'multi_state_unavailable': [],
    },
    'limited_by_available_multi_state': {
        'state_available': 'any',
        'state_unavailable': [],
        'multi_state_available': ['bimbo'],
        'multi_state_unavailable': [],
    },
    'limited_by_unavailable_multi_state': {
        'state_available': 'any',
        'state_unavailable': [],
        'multi_state_available': 'any',
        'multi_state_unavailable': ['bimbo'],
    },
    'limited_by_available': {
        'state_available': ['bimbo'],
        'state_unavailable': [],
        'multi_state_available': ['bimbo'],
        'multi_state_unavailable': [],
    },
    'limited_by_unavailable': {
        'state_available': 'any',
        'state_unavailable': ['bimbo'],
        'multi_state_available': 'any',
        'multi_state_unavailable': ['bimbo'],
    },
}
cluster_variants = {
    'unknown-unknown': {'state': 'unknown', '_multi_state': ['unknown']},
    'bimbo-unknown': {'state': 'bimbo', '_multi_state': ['unknown']},
    'unknown-bimbo': {'state': 'unknown', '_multi_state': ['bimbo']},
    'bimbo-bimbo': {'state': 'bimbo', '_multi_state': ['bimbo']},
}
expected_results = {
    'unknown-unknown': {
        'unlimited': True,
        'limited_by_available_state': False,
        'limited_by_unavailable_state': True,
        'limited_by_available_multi_state': False,
        'limited_by_unavailable_multi_state': True,
        'limited_by_available': False,
        'limited_by_unavailable': True,
    },
    'bimbo-unknown': {
        'unlimited': True,
        'limited_by_available_state': True,
        'limited_by_unavailable_state': False,
        'limited_by_available_multi_state': False,
        'limited_by_unavailable_multi_state': True,
        'limited_by_available': False,
        'limited_by_unavailable': False,
    },
    'unknown-bimbo': {
        'unlimited': True,
        'limited_by_available_state': False,
        'limited_by_unavailable_state': True,
        'limited_by_available_multi_state': True,
        'limited_by_unavailable_multi_state': False,
        'limited_by_available': False,
        'limited_by_unavailable': False,
    },
    'bimbo-bimbo': {
        'unlimited': True,
        'limited_by_available_state': True,
        'limited_by_unavailable_state': False,
        'limited_by_available_multi_state': True,
        'limited_by_unavailable_multi_state': False,
        'limited_by_available': True,
        'limited_by_unavailable': False,
    },
}


class ActionAllowTest(TestCase):
    """Tests for `cm.models.Action.allowed` method"""

    def test_variants(self):
        bundle = utils.gen_bundle()
        prototype = utils.gen_prototype(bundle, 'cluster')
        cluster = utils.gen_cluster(bundle=bundle, prototype=prototype)
        action = utils.gen_action(bundle=bundle, prototype=prototype)

        for state_name, cluster_states in cluster_variants.items():
            for cl_attr, cl_value in cluster_states.items():
                setattr(cluster, cl_attr, cl_value)
            cluster.save()

            for req_name, req_states in plausible_action_variants.items():
                for act_attr, act_value in req_states.items():
                    setattr(action, act_attr, act_value)
                action.save()

                self.assertIs(action.allowed(cluster), expected_results[state_name][req_name])
