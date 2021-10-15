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

"""UI tests for config field descriptions"""

import os

import allure
import pytest
from adcm_pytest_plugin.utils import get_data_dir

from tests.ui_tests.app.configuration import Configuration

# pylint: disable=redefined-outer-name


DATADIR = get_data_dir(__file__)
BUNDLES = os.path.join(os.path.dirname(__file__), "../stack/")

NO_TOOLTIP_FIELDS = ['string_required_by_default_without_type', 'string_read_only_any_without_type']


@pytest.fixture()
@allure.step('Upload bundle, create cluster and add service')
def service(sdk_client_fs):
    """Upload bundle, create cluster and add service"""
    bundle = sdk_client_fs.upload_from_fs(DATADIR)
    cluster = bundle.cluster_create(name='tooltips')
    cluster.service_add(name='tooltips_test')
    return cluster.service(name="tooltips_test")


@pytest.fixture()
@allure.title('Open Service Configuration page')
def ui_config(app_fs, service, login_to_adcm_over_api):  # pylint: disable=unused-argument
    """Open Service Configuration page"""
    return Configuration.from_service(app_fs, service)


@pytest.fixture()
@allure.step('Get tooltips and descriptions')
def tooltips(ui_config, service):
    """Get tooltips and descriptions"""
    config = service.prototype().config
    descriptions = [field['description'] for field in config[1:] if field['description'] != ""]
    app_fields = ui_config.get_app_fields()
    tooltips = []
    for app_field in app_fields:
        ttip = app_field.text.split(":")[0]
        if ttip in descriptions and ttip != "":
            tooltips.append(ui_config.get_tooltip_text_for_element(app_field))
    return tooltips, descriptions


def test_tooltip_presented(tooltips):
    """Test tooltips are presented"""
    with allure.step('Check that field have description tooltip presented'):
        assert len(tooltips[0]) == 8


@pytest.mark.xfail()
def test_tooltip_text(tooltips):
    """Test tooltip text"""
    with allure.step('Check description in tooltip'):
        assert set(tooltips[0]).issubset(set(tooltips[1]))


@pytest.mark.parametrize("field", NO_TOOLTIP_FIELDS)
def test_tooltip_not_presented(field, ui_config):
    """Test tooltip are absent"""
    textboxes = ui_config.get_textboxes()
    with allure.step("Check that we haven't tooltip for fields without description"):
        for textbox in textboxes:
            if field == textbox.text.split(":")[0]:
                assert not ui_config.check_tooltip_for_field(textbox)
