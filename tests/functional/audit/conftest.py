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

"""conftest for audit tests"""

from pathlib import Path
from typing import NamedTuple

import pytest

from tests.library.audit.checkers import AuditLogChecker
from tests.library.audit.readers import YAMLReader, ParsedAuditLog

# pylint: disable=redefined-outer-name

AUDIT_LOG_SCENARIOS_DIR = Path(__file__).parent / 'scenarios'


class ScenarioArg(NamedTuple):
    """Wrapper for argument for audit log parser"""

    filename: str
    context: dict


@pytest.fixture(scope="session")
def audit_log_scenarios_reader() -> YAMLReader:
    """Create YAML reader aimed to scenarios dir"""
    return YAMLReader(AUDIT_LOG_SCENARIOS_DIR)


@pytest.fixture()
def parsed_audit_log(request, audit_log_scenarios_reader) -> ParsedAuditLog:
    """Parse given file with given context"""
    if not request.param or not isinstance(request.param, ScenarioArg):
        raise ValueError(f'Param is required and it has to be {ScenarioArg.__class__.__name__}')
    return audit_log_scenarios_reader.parse(request.param.filename, request.param.context)


@pytest.fixture()
def audit_log_checker(parsed_audit_log) -> AuditLogChecker:
    """Create audit log checker based on parsed audit log"""
    return AuditLogChecker(parsed_audit_log)
