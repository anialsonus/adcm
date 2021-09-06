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

from unittest.mock import Mock
from django.test import TestCase

import cm.signal_callbacks  # pylint: disable=unused-import
import cm.status_api
from cm import models
from cm.api_context import ctx
from cm.unit_tests import utils


class ConcernSignalTest(TestCase):
    """Tests for obj.concerns change signals"""

    @classmethod
    def setUpClass(cls):
        cm.status_api.api_post = Mock()
        super().setUpClass()

    def setUp(self):
        self.hierarchy = utils.generate_hierarchy()
        self.lock = utils.gen_concern_item(models.ConcernType.Lock)

    def test_addition(self):
        event_queue = ctx.event.events
        for obj in self.hierarchy.values():
            event_queue.clear()
            obj.concerns.add(self.lock)
            self.assertEqual(len(event_queue), 1)

    def test_removal(self):
        event_queue = ctx.event.events
        for obj in self.hierarchy.values():
            event_queue.clear()
            obj.concerns.remove(self.lock)
            self.assertEqual(len(event_queue), 1)

    def test_concern_item_delete(self):
        event_queue = ctx.event.events
        for obj in self.hierarchy.values():
            obj.concerns.add(self.lock)
        event_queue.clear()

        self.lock.delete()
        self.assertEqual(len(event_queue), len(self.hierarchy))
