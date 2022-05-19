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

"""Common fixtures and tools for ADCM tests"""

# pylint: disable=W0621
import os
import sys
import tarfile
from pathlib import PosixPath
from typing import Optional, List, Tuple, Union

import allure
import pytest
import yaml

from _pytest.python import Function, FunctionDefinition, Module
from adcm_client.objects import ADCMClient, User
from allure_commons.model2 import TestResult, Parameter
from allure_pytest.listener import AllureListener
from docker.utils import parse_repository_tag

pytest_plugins = "adcm_pytest_plugin"

# We have a number of calls from functional or ui_tests to cm module,
# so we need a way to extend PYTHONPATH at test time.
testdir = os.path.dirname(__file__)
rootdir = os.path.dirname(testdir)
pythondir = os.path.abspath(os.path.join(rootdir, 'python'))
sys.path.append(pythondir)

# can be used to dump it to file to create dummy bundle archives
DUMMY_CLUSTER_BUNDLE = [
    {
        'type': 'cluster',
        'name': 'test_cluster',
        'description': 'community description',
        'version': '1.5',
        'edition': 'community',
    }
]
DUMMY_ACTION = {
    'dummy_action': {
        'type': 'job',
        'script': './actions.yaml',
        'script_type': 'ansible',
        'states': {'available': 'any'},
    }
}

CLEAN_ADCM_PARAM = pytest.param({}, id="clean_adcm")
DUMMY_DATA_PARAM = pytest.param({"fill_dummy_data": True}, id="adcm_with_dummy_data")
DUMMY_DATA_FULL_PARAM = pytest.param({"fill_dummy_data": True}, id="adcm_with_dummy_data", marks=[pytest.mark.full])

CHROME_PARAM = pytest.param("Chrome")
FIREFOX_PARAM = pytest.param("Firefox", marks=[pytest.mark.full])
ONLY_CHROME_PARAM = [CHROME_PARAM]
CHROME_AND_FIREFOX_PARAM = [CHROME_PARAM, FIREFOX_PARAM]
INCLUDE_FIREFOX_MARK = "include_firefox"

TEST_USER_CREDENTIALS = "test_user", "password"


def _marker_in_node(mark: str, node: Union[FunctionDefinition, Module]) -> bool:
    """Check if mark is in own_markers of a node"""
    return any(marker.name == mark for marker in node.own_markers)


def marker_in_node_or_its_parent(mark: str, node) -> bool:
    """Check if mark is in own_markers of a node or any of its parents"""
    marker_at_this_node = _marker_in_node(mark, node)
    if marker_at_this_node or node.parent is None:
        return marker_at_this_node
    return marker_in_node_or_its_parent(mark, node.parent)


def pytest_generate_tests(metafunc):
    """
    Parametrize web_driver fixture of browser names based on run options
    """
    if 'browser' in metafunc.fixturenames:
        browsers = (
            CHROME_AND_FIREFOX_PARAM
            if marker_in_node_or_its_parent(INCLUDE_FIREFOX_MARK, metafunc.definition)
            else ONLY_CHROME_PARAM
        )
        metafunc.parametrize('browser', browsers, scope='session')


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_setup(item: Function):
    """
    Pytest hook that overrides test parameters
    In case of adcm tests, parameters in allure report don't make sense unlike test ID
    So, we remove all parameters in allure report but add one parameter with test ID
    """
    yield
    _override_allure_test_parameters(item)


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(session, config, items):  # pylint: disable=unused-argument
    """Run tests with id "adcm_with_dummy_data" after everything else"""
    items.sort(key=lambda x: 'adcm_with_dummy_data' in x.name)


def _override_allure_test_parameters(item: Function):
    """
    Overrides all pytest parameters in allure report with test ID
    """
    listener = _get_listener_by_item_if_present(item)
    if listener:
        test_result: TestResult = listener.allure_logger.get_test(None)
        test_result.parameters = [Parameter(name="ID", value=item.callspec.id)]


def _get_listener_by_item_if_present(item: Function) -> Optional[AllureListener]:
    """
    Find AllureListener instance in pytest pluginmanager
    """
    if hasattr(item, "callspec"):
        listener: AllureListener = next(
            filter(
                lambda x: isinstance(x, AllureListener),
                item.config.pluginmanager._name2plugin.values(),  # pylint: disable=protected-access
            ),
            None,
        )
        return listener
    return None


@pytest.fixture()
def bundle_archive(request, tmp_path):
    """
    Prepare tar file from dir without using bundle packer
    """
    return _pack_bundle(request.param, tmp_path)


def _pack_bundle(stack_dir, archive_dir):
    archive_name = os.path.join(archive_dir, os.path.basename(stack_dir) + ".tar")
    with tarfile.open(archive_name, "w") as tar:
        for sub in os.listdir(stack_dir):
            tar.add(os.path.join(stack_dir, sub), arcname=sub)
    return archive_name


@pytest.fixture()
def bundle_archives(request, tmp_path) -> List[str]:
    """
    Prepare multiple bundles as in bundle_archive fixture
    """
    return [_pack_bundle(bundle_path, tmp_path) for bundle_path in request.param]


@pytest.fixture(params=[[DUMMY_CLUSTER_BUNDLE]])
def create_bundle_archives(request, tmp_path: PosixPath) -> List[str]:
    """
    Create dummy bundle archives to test pagination
    It no license required in archive type of params should be List[List[dict]]
        otherwise Tuple[List[List[dict]], str] is required

    If you need licence then `params` should be of type Tuple[List[List[dict]], str]
        where first tuple item is a list of bundle configs
        and second is path to license file (for bundles with licenses)
    ! License archive is always named 'license.txt'

    :returns: list with paths to archives
    """
    archives = []
    if isinstance(request.param, list):
        bundle_configs = request.param
        license_path = 'license.txt'
    elif isinstance(request.param, tuple) and len(request.param) == 2:
        bundle_configs, license_path = request.param
    else:
        raise TypeError('Request parameter should be either List[dict] or Tuple[List[dict], str]')
    for i, config in enumerate(bundle_configs):
        archive_path = tmp_path / f'spam_bundle_{i}.tar'
        config_fp = (bundle_dir := tmp_path / f'spam_bundle_{i}') / 'config.yaml'
        bundle_dir.mkdir()
        with open(config_fp, 'w', encoding='utf_8') as config_file:
            yaml.safe_dump(config, config_file)
        with tarfile.open(archive_path, 'w') as archive:
            archive.add(config_fp, arcname='config.yaml')
            # assume that ist is declared in first item
            if 'license' in config[0]:
                license_fp = os.path.join(license_path)
                archive.add(license_fp, arcname=config[0]['license'])
        archives.append(str(archive_path))
    return archives


@pytest.fixture(scope="session")
def adcm_image_tags(cmd_opts) -> Tuple[str, str]:
    """Get tag parts of --adcm-image argument (split by ":")"""
    if not cmd_opts.adcm_image:
        pytest.fail("CLI parameter adcm_image should be provided")
    return tuple(parse_repository_tag(cmd_opts.adcm_image))  # type: ignore


# RBAC


@pytest.fixture()
@allure.title("Create test user")
def user(sdk_client_fs) -> User:
    """Create user for testing"""
    return sdk_client_fs.user_create(*TEST_USER_CREDENTIALS)


@pytest.fixture()
def user_sdk(user, adcm_fs) -> ADCMClient:  # pylint: disable=unused-argument
    """Returns ADCMClient object from adcm_client with testing user"""
    username, password = TEST_USER_CREDENTIALS
    return ADCMClient(url=adcm_fs.url, user=username, password=password)
