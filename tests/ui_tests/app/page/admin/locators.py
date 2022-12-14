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

"""Admin page locators"""

from selenium.webdriver.common.by import By
from tests.ui_tests.app.page.common.configuration.locators import CommonConfigMenu
from tests.ui_tests.core.locators import BaseLocator, TemplateLocator


class CommonAdminPagesLocators:
    """Common locators for admin pages"""

    create_btn = BaseLocator(By.CSS_SELECTOR, "app-add-button button", "Create button")
    delete_btn = BaseLocator(By.CSS_SELECTOR, ".controls>button", "Delete Group button")
    field_error = TemplateLocator(By.XPATH, "//mat-error[contains(text(), '{}')]", 'Error "{}"')
    item = BaseLocator(By.CSS_SELECTOR, "adwp-selection-list mat-list-option", "select items")
    save_update_btn = BaseLocator(
        By.XPATH,
        "//button[./span[contains(text(), 'Add') or contains(text(), 'Update')]]",
        "Save/Update button",
    )
    cancel_btn = BaseLocator(By.XPATH, "//button[./span[contains(text(), 'Cancel')]]", "Cancel button")


class FilterLocators:
    filter_btn = BaseLocator(By.CSS_SELECTOR, "app-filter .filter-toggle-button", "Filter button")
    filter_dropdown_select = BaseLocator(By.CSS_SELECTOR, "app-filter mat-select", "Filter dropdown select")
    filter_dropdown_option = BaseLocator(By.CSS_SELECTOR, "div[role='listbox'] mat-option", "Filter dropdown option")
    filter_dropdown_remove = BaseLocator(
        By.CSS_SELECTOR, "app-filter button[aria-label='Remove']", "Filter remove button"
    )


class AdminIntroLocators:
    """Locators for Admin Intro menu"""

    intro_title = BaseLocator(By.CSS_SELECTOR, ".content mat-card-header", "Intro header container")
    intro_text = BaseLocator(By.CSS_SELECTOR, ".content mat-card-content", "Intro text container")


class AdminSettingsLocators(CommonConfigMenu):
    """Locators for Admin Settings menu"""


class AdminUsersLocators(FilterLocators):
    """Locators for Admin Users menu"""

    create_user_button = BaseLocator(By.XPATH, "//button[@adcm_test='create-btn']", "Add user button")
    user_row = BaseLocator(By.CSS_SELECTOR, "mat-row", "Table row")
    filter_btn = BaseLocator(By.CSS_SELECTOR, "app-server-filter .filter-toggle-button", "Filter button")
    filter_dropdown_select = BaseLocator(By.CSS_SELECTOR, "app-server-filter mat-select", "Filter dropdown select")
    filter_dropdown_option = BaseLocator(By.CSS_SELECTOR, "div[role='listbox'] mat-option", "Filter dropdown option")
    filter_dropdown_remove = BaseLocator(
        By.CSS_SELECTOR, "app-server-filter button[aria-label='Remove']", "Filter remove button"
    )

    class Row:
        """Existing user row"""

        username = BaseLocator(By.XPATH, ".//mat-cell[2]", "Username in row")
        password = BaseLocator(By.CSS_SELECTOR, "input[data-placeholder='Password']", "Password in row")
        password_confirm = BaseLocator(
            By.CSS_SELECTOR,
            "input[data-placeholder='Confirm Password']",
            "Password confirmation in row",
        )
        confirm_update_btn = BaseLocator(
            By.XPATH,
            ".//button[.//mat-icon[text()='done']]",
            "Confirm password update button in row",
        )
        select_checkbox = BaseLocator(By.XPATH, ".//span[.//input[@type='checkbox']]", "Select user checkbox in row")
        delete_btn = BaseLocator(By.XPATH, ".//button[.//mat-icon[text()='delete']]", "Delete user button in row")

    class AddUserPopup(CommonAdminPagesLocators):
        """Popup with new user info"""

        block = BaseLocator(By.TAG_NAME, "mat-dialog-container", "Add user popup block")
        username = BaseLocator(By.NAME, "username", "New user username")
        password = BaseLocator(By.CSS_SELECTOR, "input[data-placeholder='Password']", "New user password")
        password_confirm = BaseLocator(
            By.CSS_SELECTOR,
            "input[data-placeholder='Confirm password']",
            "New user password confirmation",
        )
        adcm_admin_chbx = BaseLocator(
            By.CSS_SELECTOR,
            "mat-checkbox[formcontrolname='is_superuser']",
            "Checkbox ADCM Administrator",
        )
        first_name = BaseLocator(By.NAME, "first_name", "New user first name")
        last_name = BaseLocator(By.NAME, "last_name", "New user last name")
        email = BaseLocator(By.NAME, "email", "New user email")
        select_groups = BaseLocator(By.CSS_SELECTOR, "adwp-input-select[controlname='group']", "Select groups")
        group_item = BaseLocator(By.CSS_SELECTOR, "mat-list-option[role='option']", "Group item")

    class FilterPopup:
        """Popup for filter info"""

        block = BaseLocator(By.CSS_SELECTOR, "div[role='menu']", "Filter popup block")
        filter_item = BaseLocator(By.CSS_SELECTOR, "button[role='menuitem']", "Filter item")


class AdminGroupsLocators(CommonAdminPagesLocators):
    """Locators for Admin Groups menu"""

    class GroupRow:
        """Row with groups info"""

        checkbox = BaseLocator(By.CSS_SELECTOR, "mat-checkbox", "Group checkbox")
        name = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(2)", "Group name")
        description = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(3)", "Group description")
        users = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(4)", "Group users")

    class AddGroupPopup:
        """Locators for creating groups popup"""

        block = BaseLocator(By.CSS_SELECTOR, "app-rbac-group-form", "Add group popup block")
        title = BaseLocator(By.CSS_SELECTOR, "mat-dialog-container h3", "Popup title")
        name_input = BaseLocator(By.CSS_SELECTOR, "adwp-input[label='Group name'] input", "Input name")
        description_input = BaseLocator(By.CSS_SELECTOR, "adwp-input[label='Description'] input", "Input description")
        users_select = BaseLocator(
            By.CSS_SELECTOR, "adwp-input-select[label='Select users'] adwp-select", "select users"
        )

        class UserRow:
            """Locators for user row in creating groups popup"""

            checkbox = BaseLocator(By.CSS_SELECTOR, "mat-pseudo-checkbox", "Group checkbox")


class AdminRolesLocators(CommonAdminPagesLocators):
    """Locators for Admin Roles menu"""

    class RoleRow:
        """Row with role info"""

        checkbox = BaseLocator(By.CSS_SELECTOR, "mat-checkbox", "Role checkbox")
        name = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(2)", "Role name")
        description = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(3)", "Role description")
        permissions = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(4)", "Role permissions")

    class AddRolePopup:
        """Locators for creating roles popup"""

        block = BaseLocator(By.CSS_SELECTOR, "app-rbac-role-form", "Add role popup block")
        role_name_input = BaseLocator(
            By.CSS_SELECTOR, "adwp-input[controlname='display_name'] input", "Input for role name"
        )
        description_name_input = BaseLocator(
            By.CSS_SELECTOR,
            "adwp-input[controlname='description'] input",
            "Input for role description",
        )

        class PermissionItemsBlock:
            filter_input = BaseLocator(
                By.CSS_SELECTOR,
                ".adcm-input-rbac-permissions__selected-filter input",
                "Filter input",
            )
            item = BaseLocator(
                By.CSS_SELECTOR,
                ".adcm-input-rbac-permissions__selected-field mat-chip",
                "Selected permission item",
            )
            clear_all_btn = BaseLocator(
                By.CSS_SELECTOR,
                ".adcm-input-rbac-permissions__selected-filter-clear",
                "Clear all button",
            )

            class PermissionItem:
                name = BaseLocator(By.CSS_SELECTOR, "div", "Name")
                delete_btn = BaseLocator(By.CSS_SELECTOR, "button", "Delete button")

        class SelectPermissionsBlock:
            permissions_filters = BaseLocator(
                By.CSS_SELECTOR,
                ".adcm-rbac-permission__filter mat-chip",
                "filter item for permissions list",
            )
            permissions_search_row = BaseLocator(
                By.CSS_SELECTOR, "adwp-selection-list-actions", "Permission search row"
            )
            permissions_item_row = BaseLocator(
                By.CSS_SELECTOR, ".adcm-rbac-permission__options mat-list-option", "Permission row"
            )
            select_btn = BaseLocator(By.CSS_SELECTOR, ".adcm-rbac-permission__actions button", "Select button")

            class SelectPermissionsRow:
                checkbox = BaseLocator(By.CSS_SELECTOR, "mat-pseudo-checkbox", "Checkbox")
                name = BaseLocator(By.CSS_SELECTOR, ".mat-list-text", "Name")


class AdminPoliciesLocators(CommonAdminPagesLocators):
    """Locators for Admin Policies menu"""

    class PolicyRow:
        """Row with policy info"""

        checkbox = BaseLocator(By.CSS_SELECTOR, "mat-checkbox", "policy checkbox")
        name = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(2)", "policy name")
        description = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(3)", "policy description")
        role = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(4)", "policy role")
        users = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(5)", "policy users")
        groups = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(6)", "policy groups")
        objects = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(7)", "policy objects")

    class AddPolicyPopup:
        """Locators for creating policy popup"""

        block = BaseLocator(By.CSS_SELECTOR, "app-rbac-policy-form>mat-horizontal-stepper", "Add policy popup block")

        class FirstStep:
            """Locators for first step"""

            name_input = BaseLocator(By.CSS_SELECTOR, "input[name='name']", "Input name")
            description_input = BaseLocator(By.CSS_SELECTOR, "input[name='description']", "Input description")
            role_select = BaseLocator(By.CSS_SELECTOR, "mat-select[placeholder='Role']", "select role")
            role_item = BaseLocator(
                By.XPATH,
                "//div[./mat-option//*[@placeholderlabel='Select role']]/mat-option",
                "select items for role",
            )

            users_select = BaseLocator(By.CSS_SELECTOR, "adwp-input-select[label='User'] adwp-select", "select users")

            group_select = BaseLocator(By.CSS_SELECTOR, "adwp-input-select[label='Group'] adwp-select", "select group")

            next_btn_first = BaseLocator(
                By.CSS_SELECTOR,
                "app-rbac-policy-form-step-one~div button.mat-stepper-next",
                "Next button from first step",
            )

        class SecondStep:
            """Locators for second step"""

            back_btn_second = BaseLocator(
                By.CSS_SELECTOR,
                "app-rbac-policy-form-step-two~div button[matstepperprevious]",
                "Back button from second step",
            )
            cluster_select = BaseLocator(
                By.XPATH, "//div[./span//span[text()='Cluster']]//adwp-select", "select cluster"
            )
            service_select = BaseLocator(
                By.XPATH, "//div[./span//span[text()='Service']]//mat-select", "select service"
            )
            service_item = BaseLocator(By.CSS_SELECTOR, ".mat-select-panel mat-option", "select service item")
            provider_select = BaseLocator(
                By.CSS_SELECTOR, "app-parametrized-by-provider adwp-select", "select provider"
            )
            parent_select = BaseLocator(By.XPATH, "//div[./span//span[text()='Parent']]//adwp-select", "select parent")
            hosts_select = BaseLocator(By.CSS_SELECTOR, "app-parametrized-by-host mat-form-field", "select hosts")
            next_btn_second = BaseLocator(
                By.CSS_SELECTOR,
                "app-rbac-policy-form-step-two~div .mat-stepper-next",
                "Next button from second step",
            )

        class ThirdStep:
            """Locators for third step"""

            back_btn_third = BaseLocator(
                By.CSS_SELECTOR,
                "app-rbac-policy-form-step-three~div button[matstepperprevious]",
                "Next button from third step",
            )
            cancel_btn = BaseLocator(By.XPATH, "//button[./span[text()='Cancel']]", "Cancel button")


class AuditFilter:
    button = BaseLocator(By.XPATH, "//app-server-filter//mat-icon", "Filters button")
    menu = BaseLocator(By.XPATH, "//div[@role='menu']", "Filters choice menu")
    choice = BaseLocator(By.TAG_NAME, "button", "Filters choice item")
    block = BaseLocator(By.TAG_NAME, "form", "Form container for picked filters")
    remove_button = BaseLocator(By.XPATH, "//mat-icon[text()='close']", "Remove filter button")
    refresh_button = BaseLocator(By.XPATH, "//mat-icon[text()='refresh']", "Refresh filter button")

    # not very accurate, but for works fine for operations audit
    dropdown_option = BaseLocator(By.TAG_NAME, "mat-option", "Filter dropdown option")


class OperationsAuditLocators:
    title = BaseLocator(By.TAG_NAME, "mat-card-title", "Audit operations list page's title")

    class Filter(AuditFilter):
        class Item:
            username = BaseLocator(By.XPATH, ".//input[@data-placeholder='Username']", "Username filter item")
            object_name = BaseLocator(By.XPATH, ".//input[@data-placeholder='Object name']", "Object name filter item")
            object_type = BaseLocator(
                By.XPATH, ".//mat-select[.//span[text()='Object type']]", "Object type filter item"
            )
            operation_type = BaseLocator(
                By.XPATH, ".//mat-select[.//span[text()='Operation type']]", "Operation type filter item"
            )
            operation_result = BaseLocator(
                By.XPATH, ".//mat-select[.//span[text()='Operation result']]", "Operation result filter item"
            )
            operation_time = BaseLocator(By.TAG_NAME, "mat-date-range-input", "Operation time filter item")

    class Row:
        object_type = BaseLocator(By.CSS_SELECTOR, "mat-cell:first-child", "Object type in row")
        object_name = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(2)", "Object name in row")
        operation_name = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(3)", "Operation name in row")
        operation_type = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(4)", "Operation type in row")
        operation_result = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(5)", "Operation result in row")
        operation_time = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(6)", "Operation time in row")
        username = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(7)", "Username in row")
        show_changes = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(8) button", "Show changes button in row")


class LoginAuditLocators:
    title = BaseLocator(By.TAG_NAME, "mat-card-title", "Audit login list page's title")

    class Filter(AuditFilter):
        class Item:
            login = BaseLocator(By.XPATH, ".//input[@data-placeholder='Login']", "Login filter item")
            result = BaseLocator(By.XPATH, ".//mat-select[.//span[text()='Result']]", "Result filter item")

    class Row:
        login = BaseLocator(By.CSS_SELECTOR, "mat-cell:first-child", "Login in row")
        result = BaseLocator(By.CSS_SELECTOR, "mat-cell:nth-child(2)", "Result in row")
        login_time = BaseLocator(By.CSS_SELECTOR, "mat-cell:last-child", "Login time in row")
