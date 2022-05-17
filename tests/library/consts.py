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

"""Common consts for tests"""
from enum import Enum


class States:  # pylint: disable=too-few-public-methods
    """Possible states dataclass"""

    failed = 'failed'
    success = 'success'


class MessageStates:  # pylint: disable=too-few-public-methods
    """Possible states messages dataclass"""

    fail_msg = 'fail_msg'
    success_msg = 'success_msg'


class HTTPMethod(Enum):  # pylint: disable=too-few-public-methods
    """HTTP methods"""

    GET = 'get'
    POST = 'post'
    PUT = 'put'
    PATCH = 'patch'
    DELETE = 'delete'
