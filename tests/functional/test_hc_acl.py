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

"""Tests for ADCM HC ACL"""

import pytest
from adcm_client.objects import ADCMClient
from adcm_pytest_plugin.utils import get_data_subdirs_as_parameters

cases, ids = get_data_subdirs_as_parameters(__file__, "syntax", "positive")


@pytest.mark.parametrize("bundle", cases, ids=ids)
def test_posite_upload(sdk_client_fs: ADCMClient, bundle):
    """Test upload bundle with action with HC ACL variants"""
    sdk_client_fs.upload_from_fs(bundle)
