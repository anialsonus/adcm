from selenium.common import TimeoutException
from selenium.webdriver.remote.webelement import WebElement
from tests.ui_tests.app.helpers.locator import BaseLocator


def check_elements_are_displayed(page, locators: list[BaseLocator]) -> None:
    for loc in locators:
        assert page.is_element_displayed(loc), f"Locator {loc.name} isn't displayed on page {page.driver.current_url}"


def check_element_is_hidden(page, element: BaseLocator | WebElement, timeout: int | None = None) -> None:
    """Raises assertion error if element is still visible after timeout"""
    try:
        page.wait_element_hide(element, timeout)
    except TimeoutException as e:
        raise AssertionError(e.msg) from e


def check_element_is_visible(page, element: BaseLocator | WebElement, timeout: int | None = None) -> None:
    """Raises assertion error if element is not visible after timeout"""
    try:
        page.wait_element_visible(element, timeout)
    except TimeoutException as e:
        raise AssertionError(e.msg) from e
