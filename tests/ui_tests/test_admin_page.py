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

# pylint: disable=redefined-outer-name,no-self-use,too-few-public-methods

"""UI tests for /admin page"""

import os
from typing import (
    Tuple,
)

import allure
import pytest
from adcm_client.objects import (
    Bundle,
    Cluster,
    ADCMClient,
    Host,
    Service,
    Provider,
)
from adcm_pytest_plugin import utils
from adcm_pytest_plugin.utils import random_string

from tests.ui_tests.app.app import ADCMTest
from tests.ui_tests.app.page.admin.page import (
    AdminIntroPage,
    AdminUsersPage,
    AdminSettingsPage,
    AdminRolesPage,
    AdminGroupsPage,
    AdminRoleInfo,
    AdminGroupInfo,
    AdminPoliciesPage,
    AdminPolicyInfo,
)
from tests.ui_tests.app.page.login.page import LoginPage
from tests.ui_tests.utils import expect_rows_amount_change

BUNDLE = "cluster_with_services"
CLUSTER_NAME = "test_cluster"
SERVICE_NAME = "test_service_1"
FIRST_COMPONENT_NAME = "first"
PROVIDER_NAME = 'test_provider'
HOST_NAME = 'test-host'


# !===== Fixtures =====!


pytestmark = [pytest.mark.usefixtures("login_to_adcm_over_api")]


@pytest.fixture()
# pylint: disable-next=unused-argument
def users_page(app_fs: ADCMTest) -> AdminUsersPage:
    """Get Admin Users Page"""
    return AdminUsersPage(app_fs.driver, app_fs.adcm.url).open()


@pytest.fixture()
# pylint: disable-next=unused-argument
def settings_page(app_fs: ADCMTest) -> AdminSettingsPage:
    """Get Admin Settings Page"""
    return AdminSettingsPage(app_fs.driver, app_fs.adcm.url).open()


@allure.step("Upload cluster bundle")
def cluster_bundle(sdk_client_fs: ADCMClient, data_dir_name: str) -> Bundle:
    """Upload cluster bundle"""

    return sdk_client_fs.upload_from_fs(os.path.join(utils.get_data_dir(__file__), data_dir_name))


@pytest.fixture()
def create_cluster_with_service(sdk_client_fs: ADCMClient) -> Tuple[Cluster, Service]:
    """Create cluster and add service"""

    bundle = cluster_bundle(sdk_client_fs, BUNDLE)
    cluster = bundle.cluster_create(name=CLUSTER_NAME)
    return cluster, cluster.service_add(name=SERVICE_NAME)


@pytest.fixture()
def create_cluster_with_component(
    create_cluster_with_service: Tuple[Cluster, Service], sdk_client_fs: ADCMClient
) -> Tuple[Cluster, Service, Host, Provider]:
    """Create cluster with component"""

    cluster, service = create_cluster_with_service
    provider_bundle = sdk_client_fs.upload_from_fs(os.path.join(utils.get_data_dir(__file__), 'provider'))
    provider = provider_bundle.provider_create('test_provider')
    host = provider.host_create('test-host')
    cluster.host_add(host)
    cluster.hostcomponent_set((host, service.component(name=FIRST_COMPONENT_NAME)))
    return cluster, service, host, provider


# !===== Tests =====!


class TestAdminIntroPage:
    """Tests for the /admin/intro"""

    def test_open_by_tab_admin_intro_page(self, app_fs):
        """Test open /admin/intro from left menu"""

        users_page = AdminUsersPage(app_fs.driver, app_fs.adcm.url).open()
        intro_page = users_page.open_settings_menu()
        intro_page.check_all_elements()
        intro_page.check_admin_toolbar()


class TestAdminSettingsPage:
    """Tests for the /admin/roles"""

    @pytest.mark.smoke()
    def test_open_by_tab_admin_settings_page(self, app_fs):
        """Test open /admin/settings from left menu"""

        intro_page = AdminIntroPage(app_fs.driver, app_fs.adcm.url).open()
        settings_page = intro_page.open_settings_menu()
        settings_page.check_all_elements()
        settings_page.check_admin_toolbar()

    @pytest.mark.full()
    def test_settings_filter(self, settings_page: AdminSettingsPage):
        """Apply different filters on Admin Settings page"""
        params = {
            'search_text': 'ADCM',
            'field_display_name': "ADCM's URL",
            'group': 'Global Options',
        }
        get_rows_func = settings_page.config.get_all_config_rows
        with allure.step(
            f'Search {params["search_text"]} and check {params["field_display_name"]} is presented after search'
        ):
            with expect_rows_amount_change(get_rows_func):
                settings_page.config.search(params['search_text'])
            settings_page.config.get_config_row(params["field_display_name"])
        with allure.step('Clear search'), expect_rows_amount_change(get_rows_func):
            settings_page.config.clear_search()
        with allure.step(
            f'Click on {params["group"]} group and check {params["field_display_name"]} '
            'is not presented after group roll up'
        ):
            with expect_rows_amount_change(get_rows_func):
                settings_page.config.click_on_group(params['group'])
            with pytest.raises(AssertionError):
                settings_page.config.get_config_row(params["field_display_name"])
        with allure.step(
            f'Click on {params["group"]} group and check {params["field_display_name"]} '
            'is presented after group expand'
        ):
            with expect_rows_amount_change(get_rows_func):
                settings_page.config.click_on_group(params['group'])
            settings_page.config.get_config_row(params["field_display_name"])

    @pytest.mark.full()
    def test_save_settings_with_different_name(self, settings_page: AdminSettingsPage):
        """Save settings with different name"""
        params = {'new_name': 'test_settings', 'field_display_name': 'client_id', 'field_value': '123'}
        settings_page.config.set_description(params['new_name'])
        with allure.step(f'Change value of field {params["field_display_name"]} to {params["field_value"]}'):
            config_field_row = settings_page.config.get_config_row(params['field_display_name'])
            settings_page.config.type_in_field_with_few_inputs(row=config_field_row, values=[params['field_value']])
        settings_page.config.save_config()
        settings_page.config.compare_versions(params['new_name'], 'init')
        with allure.step('Check history'):
            config_field_row = settings_page.config.get_config_row(params['field_display_name'])
            history = settings_page.config.get_history_in_row(config_field_row)
            assert len(history) == 1, f'History should has exactly one entry for field {params["field_display_name"]}'
            assert (actual_value := history[0]) == (expected_value := params['field_value']), (
                f'History entry for field {params["field_display_name"]} '
                f'should be {expected_value}, not {actual_value}'
            )

    @pytest.mark.full()
    def test_negative_values_in_adcm_config(self, settings_page: AdminSettingsPage):
        """Put negative numbers in the fields of ADCM settings"""
        params = (
            ('Log rotation from file system', -1, 'Field [Log rotation from file system] value cannot be less than 0!'),
            ('Log rotation from database', -1, 'Field [Log rotation from database] value cannot be less than 0!'),
            ('Forks', 0, 'Field [Forks] value cannot be less than 1!'),
        )

        for field, inappropriate_value, error_message in params:
            with allure.step(
                f'Set value {inappropriate_value} to field "{field}" and expect error message: {error_message}'
            ):
                config_row = settings_page.config.get_config_row(field)
                settings_page.scroll_to(config_row)
                settings_page.config.type_in_field_with_few_inputs(
                    row=config_row, values=[inappropriate_value], clear=True
                )
                settings_page.config.check_invalid_value_message(error_message)

    def test_reset_config(self, settings_page: AdminSettingsPage):
        """Change config field, save, reset"""
        params = {'field_display_name': 'client_id', 'init_value': '', 'changed_value': '123'}
        with allure.step(f'Set value of {params["field_display_name"]} to {params["changed_value"]}'):
            config_field_row = settings_page.config.get_config_row(params['field_display_name'])
            settings_page.config.type_in_field_with_few_inputs(row=config_field_row, values=[params['changed_value']])
        with allure.step('Save config'):
            settings_page.config.save_config()
            settings_page.config.assert_input_value_is(params['changed_value'], params['field_display_name'])
        with allure.step(f'Reset value of {params["field_display_name"]}'):
            config_field_row = settings_page.config.get_config_row(params['field_display_name'])
            settings_page.config.reset_to_default(config_field_row)
            settings_page.config.assert_input_value_is(params['init_value'], params['field_display_name'])


class TestAdminUsersPage:
    """Tests for the /admin/users"""

    @pytest.mark.smoke()
    def test_open_by_tab_admin_users_page(self, app_fs):
        """Test open /admin/users from left menu"""

        intro_page = AdminIntroPage(app_fs.driver, app_fs.adcm.url).open()
        users_page = intro_page.open_users_menu()
        users_page.check_all_elements()
        users_page.check_admin_toolbar()

    def test_new_user_creation(self, users_page: AdminUsersPage):
        """Create new user, change password and login with new password"""

        params = {
            'username': 'testuser',
            'password': 'test_pass',
            'new_password': 'testtest',
            'first_name': 'First',
            'last_name': 'Last',
            'email': 'priv@et.ru',
        }
        users_page.create_user(
            params['username'], params['password'], params['first_name'], params['last_name'], params['email']
        )
        with allure.step(f'Check user {params["username"]} is listed in users list'):
            assert users_page.is_user_presented(params['username']), f'User {params["username"]} was not created'
        users_page.change_user_password(params['username'], params['new_password'])
        users_page.header.logout()
        with allure.step(f'Login as user {params["username"]} with password {params["new_password"]}'):
            login_page = LoginPage(users_page.driver, users_page.base_url)
            login_page.wait_page_is_opened()
            login_page.login_user(params['username'], params['new_password'])
        with allure.step('Check login was successful'):
            AdminIntroPage(users_page.driver, users_page.base_url).wait_page_is_opened(timeout=5)

    def test_delete_user(self, users_page: AdminUsersPage):
        """Create new user, delete it and check current user can't be deleted"""

        params = {
            'username': 'testuser',
            'password': 'test_pass',
            'current_user': 'admin',
            'first_name': 'First',
            'last_name': 'Last',
            'email': 'priv@et.ru',
        }
        users_page.check_delete_button_not_presented(params['current_user'])
        with allure.step(f'Create user {params["username"]}'):
            users_page.create_user(
                params['username'], params['password'], params['first_name'], params['last_name'], params['email']
            )
            assert users_page.is_user_presented(params['username']), f'User {params["username"]} was not created'
        with allure.step(f'Delete user {params["username"]}'):
            users_page.delete_user(params['username'])
            assert not users_page.is_user_presented(
                params['username']
            ), f'User {params["username"]} should not be in users list'

    def test_change_admin_password(self, users_page: AdminUsersPage):
        """Change admin password, login with new credentials"""

        params = {'username': 'admin', 'password': 'new_pass'}
        users_page.update_user_info(params['username'], first_name='Best', last_name='Admin')
        users_page.change_user_password(**params)
        users_page.driver.refresh()
        with allure.step('Check Login page is opened'):
            login_page = LoginPage(users_page.driver, users_page.base_url)
            login_page.wait_page_is_opened()
        login_page.login_user(**params)
        with allure.step('Check login was successful'):
            AdminIntroPage(users_page.driver, users_page.base_url).wait_page_is_opened(timeout=5)


class TestAdminRolesPage:
    """Tests for the /admin/roles"""

    custom_role = AdminRoleInfo(
        name='Test_role_name',
        description='Test role description',
        permissions='Create provider, Create cluster, Create user, Remove policy',
    )

    @pytest.mark.smoke()
    def test_open_by_tab_admin_roles_page(self, app_fs):
        """Test open /admin/roles from left menu"""

        intro_page = AdminIntroPage(app_fs.driver, app_fs.adcm.url).open()
        roles_page = intro_page.open_roles_menu()
        roles_page.check_all_elements()
        roles_page.check_default_roles()
        with allure.step('Check that there are 4 default roles'):
            assert len(roles_page.table.get_all_rows()) == 4, "There should be 4 default roles"
        roles_page.check_admin_toolbar()

    def test_create_custom_role_on_roles_page(self, app_fs):
        """Test create a role on /admin/roles page"""

        page = AdminRolesPage(app_fs.driver, app_fs.adcm.url).open()
        page.create_role(self.custom_role.name, self.custom_role.description, self.custom_role.permissions)
        page.check_default_roles()
        page.check_custom_role(self.custom_role)

    @pytest.mark.full()
    def test_check_pagination_role_list_page(self, app_fs):
        """Test pagination on /admin/roles page"""

        page = AdminRolesPage(app_fs.driver, app_fs.adcm.url).open()
        with allure.step("Create 11 roles"):
            for _ in range(7):
                page.create_role(
                    f"{self.custom_role.name}_{random_string()}",
                    self.custom_role.description,
                    self.custom_role.permissions,
                )
        page.table.check_pagination(second_page_item_amount=1)

    def test_check_role_popup_on_roles_page(self, app_fs):
        """Test changing a role on /admin/roles page"""

        custom_role_changed = AdminRoleInfo(
            name='Test_another_name',
            description='Test role description 2',
            permissions='Upload bundle',
        )

        page = AdminRolesPage(app_fs.driver, app_fs.adcm.url).open()
        page.create_role(self.custom_role.name, self.custom_role.description, self.custom_role.permissions)
        page.open_role_by_name(self.custom_role.name)
        with allure.step("Check that update unavailable without the role name"):
            page.fill_role_name_in_role_popup(" ")
            page.check_save_button_disabled()
            page.check_field_error_in_role_popup('Role name is required.')
            page.check_field_error_in_role_popup('Role name too short.')
            page.fill_role_name_in_role_popup("")
            page.check_save_button_disabled()
            page.check_field_error_in_role_popup("Role name is required.")
            page.fill_role_name_in_role_popup("йй")
            page.check_field_error_in_role_popup("Role name is not correct.")
        with allure.step("Check that update unavailable without permissions"):
            page.remove_permissions_in_add_role_popup(permissions_to_remove=self.custom_role.permissions.split(", "))
            page.check_save_button_disabled()
            for permission in self.custom_role.permissions.split(", "):
                page.select_permission_in_add_role_popup(permission)
            page.remove_permissions_in_add_role_popup(permissions_to_remove=None, all_permissions=True)
            page.check_save_button_disabled()
        page.fill_role_name_in_role_popup(custom_role_changed.name)
        page.fill_description_in_role_popup(custom_role_changed.description)
        page.select_permission_in_add_role_popup(custom_role_changed.permissions)
        page.click_save_btn_in_role_popup()
        page.check_default_roles()
        page.check_custom_role(custom_role_changed)

    def test_delete_role_from_roles_page(self, app_fs):
        """Test delete custom role on /admin/roles page"""

        page = AdminRolesPage(app_fs.driver, app_fs.adcm.url).open()
        page.create_role(self.custom_role.name, self.custom_role.description, self.custom_role.permissions)
        page.select_all_roles()
        page.click_delete_button()
        page.check_default_roles()
        with allure.step('Check that role has been deleted'):
            assert len(page.table.get_all_rows()) == 4, "There should be 4 default roles"


class TestAdminGroupsPage:
    """Tests for the /admin/groups"""

    custom_group = AdminGroupInfo(name='Test_group', description='Test description', users='admin')

    @pytest.mark.smoke()
    def test_open_by_tab_admin_groups_page(self, app_fs):
        """Test open /admin/groups from left menu"""

        intro_page = AdminIntroPage(app_fs.driver, app_fs.adcm.url).open()
        groups_page = intro_page.open_groups_menu()
        groups_page.check_all_elements()
        groups_page.check_admin_toolbar()

    def test_create_group_on_admin_groups_page(self, app_fs):
        """Test create a group on /admin/groups"""

        groups_page = AdminGroupsPage(app_fs.driver, app_fs.adcm.url).open()
        groups_page.create_custom_group(self.custom_group.name, self.custom_group.description, self.custom_group.users)
        current_groups = groups_page.get_all_groups()
        with allure.step('Check that there are 1 custom group'):
            assert len(current_groups) == 1, "There should be 1 group on the page"
            assert self.custom_group in current_groups, "Created group should be on the page"

    @pytest.mark.full()
    def test_check_pagination_groups_list_page(self, app_fs):
        """Test pagination on /admin/groups page"""

        page = AdminGroupsPage(app_fs.driver, app_fs.adcm.url).open()
        with allure.step("Create 11 groups"):
            for _ in range(11):
                page.create_custom_group(
                    f"{self.custom_group.name}_{random_string()}",
                    self.custom_group.description,
                    self.custom_group.users,
                )
        page.table.check_pagination(second_page_item_amount=1)

    def test_delete_group_from_groups_page(self, app_fs):
        """Test delete custom group on /admin/groups page"""

        page = AdminGroupsPage(app_fs.driver, app_fs.adcm.url).open()
        page.create_custom_group(self.custom_group.name, self.custom_group.description, self.custom_group.users)
        page.select_all_groups()
        page.click_delete_button()
        with allure.step('Check that group has been deleted'):
            assert len(page.table.get_all_rows()) == 0, "There should be 0 groups"


class TestAdminPolicyPage:
    """Tests for the /admin/policies"""

    custom_role_name = 'Test_Role'
    custom_policy = AdminPolicyInfo(
        name="Test policy name",
        description="Test policy description",
        role="ADCM User",
        users="admin, status",
        groups=None,
        objects=None,
    )

    @allure.step('Check custome policy')
    def check_custom_policy(self, policies_page):
        """Check that there is only one created policy with expected params"""

        current_policies = policies_page.get_all_policies()
        assert len(current_policies) == 1, "There should be 1 policy on the page"
        assert current_policies == [self.custom_policy], "Created policy should be on the page"

    @pytest.mark.smoke()
    def test_open_by_tab_admin_policies_page(self, app_fs):
        """Test open /admin/policies from left menu"""

        intro_page = AdminIntroPage(app_fs.driver, app_fs.adcm.url).open()
        policies_page = intro_page.open_policies_menu()
        policies_page.check_all_elements()
        policies_page.check_admin_toolbar()

    def test_create_policy_on_admin_groups_page(self, app_fs):
        """Test create a group on /admin/policies"""

        policies_page = AdminPoliciesPage(app_fs.driver, app_fs.adcm.url).open()
        policies_page.create_policy(
            policy_name=self.custom_policy.name,
            description=self.custom_policy.description,
            role=self.custom_policy.role,
            users=self.custom_policy.users,
        )
        self.check_custom_policy(policies_page)

    @pytest.mark.full()
    def test_check_pagination_policy_list_page(self, app_fs):
        """Test pagination on /admin/policies page"""

        policies_page = AdminPoliciesPage(app_fs.driver, app_fs.adcm.url).open()
        with allure.step("Create 11 policies"):
            for i in range(11):
                policies_page.create_policy(
                    policy_name=f"{self.custom_policy.name}_{i}",
                    description=self.custom_policy.description,
                    role=self.custom_policy.role,
                    users=self.custom_policy.users,
                )
        policies_page.table.check_pagination(second_page_item_amount=1)

    def test_delete_policy_from_policies_page(self, app_fs):
        """Test delete custom group on /admin/policies page"""

        policies_page = AdminPoliciesPage(app_fs.driver, app_fs.adcm.url).open()
        policies_page.create_policy(
            policy_name=self.custom_policy.name,
            description=self.custom_policy.description,
            role=self.custom_policy.role,
            users=self.custom_policy.users,
        )
        policies_page.select_all_policies()
        policies_page.click_delete_button()
        with allure.step('Check that policy has been deleted'):
            assert len(policies_page.table.get_all_rows()) == 0, "There should be 0 policies on the page"

    @pytest.mark.parametrize(
        ("clusters", "services", "providers", "hosts", "parents", "role_name"),
        [
            (CLUSTER_NAME, None, None, None, None, 'View cluster configurations'),
            (None, SERVICE_NAME, None, None, CLUSTER_NAME, 'View service configurations'),
            (None, None, PROVIDER_NAME, None, None, 'View provider configurations'),
            (None, None, None, HOST_NAME, None, 'View host configurations'),
            (None, SERVICE_NAME, None, None, CLUSTER_NAME, 'View component configurations'),
            (CLUSTER_NAME, None, None, None, None, 'View cluster configurations, View service configurations'),
            (
                None,
                SERVICE_NAME,
                None,
                None,
                CLUSTER_NAME,
                'View cluster configurations, View service configurations, View component configurations, '
                'View host configurations',
            ),
            (None, None, PROVIDER_NAME, None, None, 'View provider configurations, View host configurations'),
            (None, None, None, HOST_NAME, None, 'View provider configurations, View host configurations'),
        ],
    )
    def test_check_policy_popup_for_entities(
        self,
        sdk_client_fs,
        app_fs,
        create_cluster_with_component,
        clusters,
        services,
        providers,
        hosts,
        parents,
        role_name,
    ):
        """Test creating policy"""

        self.custom_policy.role = self.custom_role_name
        self.custom_policy.objects = clusters or services or providers or hosts
        with allure.step("Create test role"):
            sdk_client_fs.role_create(
                name=self.custom_role_name,
                display_name=self.custom_role_name,
                child=[{"id": sdk_client_fs.role(name=r).id} for r in role_name.split(", ")],
            )
        policies_page = AdminPoliciesPage(app_fs.driver, app_fs.adcm.url).open()
        policies_page.create_policy(
            policy_name=self.custom_policy.name,
            description=self.custom_policy.description,
            role=self.custom_policy.role,
            users=self.custom_policy.users,
            clusters=clusters,
            services=services,
            parent=CLUSTER_NAME,
            providers=providers,
            hosts=hosts,
        )
        self.check_custom_policy(policies_page)
