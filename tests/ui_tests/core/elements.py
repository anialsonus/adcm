from operator import attrgetter
from typing import Any, Callable, Iterable, Protocol, Type, TypeVar

from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement
from tests.ui_tests.core.interactors import Interactor
from tests.ui_tests.core.locators import BaseLocator, Descriptor, Locator


class AutoChildElement:
    Locators: Type
    _element: WebElement
    _view: Interactor

    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, "Locators"):
            raise ValueError("Children locators should be available as 'Locators' in class")

        locator_fields: Iterable[tuple[str, Locator]] = filter(
            lambda i: isinstance(i[1], Locator),
            map(
                lambda i: (i, getattr(cls.Locators, i)),
                dir(cls.Locators),
            ),
        )

        for name, locator in locator_fields:
            if Descriptor.SERVICE in locator.flags:
                continue

            if Descriptor.BUTTON in locator.flags:
                setattr(cls, f"{name}_button", _build_property(locator))

            if Descriptor.ELEMENT in locator.flags:
                setattr(cls, f"{name}_element", _build_property(locator))

            if Descriptor.INPUT in locator.flags:
                setattr(cls, f"{name}_input", _build_input(locator))

            # place "same named" properties after this check
            if name in dir(cls):
                continue

            if Descriptor.TEXT in locator.flags:
                setattr(cls, name, _build_property(locator, attrgetter("text")))
            else:
                setattr(cls, name, _build_property(locator))

        return super().__new__(cls)

    def __init__(
        self, parent_element: WebElement, driver: WebDriver | None = None, interactor: Interactor | None = None
    ):
        if not (driver or interactor):
            raise RuntimeError("Either driver or interactor should be provided")

        self._element = parent_element
        self._view = interactor or Interactor(driver=driver, default_timeout=0.5)


class DialogLocatorsLike(Protocol):
    body: BaseLocator


class AutoChildDialog(AutoChildElement):

    Locators: DialogLocatorsLike

    @classmethod
    def wait_opened(cls, driver: WebDriver | None = None, interactor: Interactor | None = None):
        if not (driver or interactor):
            raise ValueError("Provide either 'driver' or 'interactor'")

        interactor = interactor or Interactor(driver=driver, default_timeout=0.5)
        interactor.wait_element_visible(cls.Locators.body, timeout=5)
        return cls(parent_element=interactor.find_element(cls.Locators.body), interactor=interactor)

    def wait_closed(self):
        self._view.wait_element_hide(self.Locators.body, timeout=5)


def _build_property(locator: Locator, retrieve: Callable[[WebElement], Any] = lambda element: element) -> property:
    # pylint: disable-next=protected-access
    return property(lambda self: retrieve(self._view.find_child(element=self._element, child=locator)))


def _build_input(locator: Locator) -> property:
    return property(  # pylint: disable-next=protected-access
        lambda self: Input(element=self._view.find_child(element=self._element, child=locator), interactor=self._view)
    )


# !===== Element Wrappers =====!


class Input:
    def __init__(self, element: WebElement, interactor: Interactor):
        self.element = element
        self._view = interactor

    @property
    def value(self) -> str:
        return self.element.get_attribute("value")

    def fill(self, value: str) -> None:
        self._view.send_text_to_element(self.element, value, timeout=3)

    def clear(self):
        self._view.clear_by_keys(self.element)


# !===== Mixins =====!

T = TypeVar("T")


class TableLike(Protocol):
    def get_all_rows(self, timeout) -> list[WebElement]:
        """Get all rows of table"""


class ObjectRowMixin:
    # type of AutoChildElement's child
    ROW_CLASS: Type[T]
    table: TableLike
    _driver: WebDriver

    def get_row(self, predicate: Callable[[T], bool]) -> T:
        suitable_rows = self.get_rows(predicate=predicate)

        if suitable_rows:
            return suitable_rows[0]

        raise AssertionError(f"No suitable {self.ROW_CLASS} found")

    def get_rows(self, predicate: Callable[[T], bool] = lambda _: True) -> tuple[T, ...]:
        return tuple(
            filter(
                predicate,
                map(
                    lambda element: self.ROW_CLASS(parent_element=element, driver=self._driver),
                    self.table.get_all_rows(timeout=1),
                ),
            )
        )
