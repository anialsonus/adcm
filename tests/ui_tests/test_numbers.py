import pytest
# pylint: disable=W0611, W0621

from adcm_client.objects import ADCMClient

from adcm_pytest_plugin.utils import parametrize_by_data_subdirs, get_data_dir

from tests.ui_tests.app.locators import Common
from tests.ui_tests.app.pages import LoginPage
from tests.ui_tests.app.configuration import Configuration


RANGE_VALUES = [("float", 0.15), ("float", 0), ("float", -1.2),
                ("integer", 4), ("integer", 0), ("integer", -3)]


@pytest.fixture()
def login(app_fs):
    app_fs.driver.get(app_fs.adcm.url)
    login = LoginPage(app_fs.driver)
    login.login("admin", "admin")


@parametrize_by_data_subdirs(__file__, 'bundles')
def test_number_validation(path, app_fs, login):
    """Check that we have errors and save button is not active
     for number field with values out of range
    """
    _ = login
    sdk_client_fs = ADCMClient(api=app_fs.adcm.api)
    bundle = sdk_client_fs.upload_from_fs(path)
    cluster_name = path.split("/")[-1]
    cluster = bundle.cluster_create(name=cluster_name)
    config = Configuration(app_fs.driver,
                           "{}/cluster/{}/config".format(app_fs.adcm.url, cluster.cluster_id))
    assert config.save_button_status()
    fields = config.get_app_fields()
    form_field = fields[0].find_elements(*Common.mat_form_field)[0]
    config.clear_input_element(form_field)
    assert not config.save_button_status()
    config.assert_form_field_text_equal(fields[0], "Field [numbers_test] is required!")
    config.set_element_value_in_input(form_field, "asdsa")
    config.assert_form_field_text_equal(fields[0], "Field [numbers_test] is invalid!")
    assert not config.save_button_status()
    config.set_element_value_in_input(form_field, "-111111")
    assert not config.save_button_status()
    config.assert_form_field_text_in(fields[0], "Field [numbers_test] value cannot be less than")
    config.set_element_value_in_input(form_field, "111111")
    assert not config.save_button_status()
    config.assert_form_field_text_in(fields[0],
                                     "Field [numbers_test] value cannot be greater than")


@pytest.mark.parametrize("number_type, value", RANGE_VALUES)
def test_number_in_range_values(value, app_fs, number_type, login):
    """Check that save button active for number fields in min-max range
    """
    _ = login
    sdk_client_fs = ADCMClient(api=app_fs.adcm.api)
    path = get_data_dir(__file__) + "/bundles/{}-positive_and_negative".format(number_type)
    bundle = sdk_client_fs.upload_from_fs(path)
    cluster_name = path.split("/")[-1]
    cluster = bundle.cluster_create(name=cluster_name)
    config = Configuration(app_fs.driver,
                           "{}/cluster/{}/config".format(app_fs.adcm.url, cluster.cluster_id))
    fields = config.get_app_fields()
    form_field = fields[0].find_elements(*Common.mat_form_field)[0]
    config.set_element_value_in_input(form_field, str(value))
    assert config.save_button_status()


def test_float_in_integer_field(app_fs, login):
    """Check that we cannot set float in integer field
    """
    _ = login
    sdk_client_fs = ADCMClient(api=app_fs.adcm.api)
    path = get_data_dir(__file__) + "/bundles/integer-positive_and_negative"
    bundle = sdk_client_fs.upload_from_fs(path)
    cluster_name = path.split("/")[-1]
    cluster = bundle.cluster_create(name=cluster_name)
    config = Configuration(app_fs.driver,
                           "{}/cluster/{}/config".format(app_fs.adcm.url, cluster.cluster_id))
    fields = config.get_app_fields()
    form_field = fields[0].find_elements(*Common.mat_form_field)[0]
    config.set_element_value_in_input(form_field, "1.2")
    assert not config.save_button_status()
    fields = config.get_app_fields()
    config.assert_form_field_text_equal(fields[0], "Field [numbers_test] is invalid!")
