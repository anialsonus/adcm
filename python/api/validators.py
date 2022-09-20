import re
import string

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import RegexValidator

from cm.errors import AdcmEx


class RegExValidator(RegexValidator):
    def __init__(self, regex: str, *args, error_code: str, error_msg: str = "", **kwargs):
        super().__init__(regex, *args, **kwargs)
        self.error_code = error_code
        self.error_msg = error_msg

    def __call__(self, value):
        try:
            super().__call__(value)
        except DjangoValidationError as e:
            raise AdcmEx(code=self.error_code, msg=self.error_msg.format(value=value)) from e


def cluster_name_validator(value: str) -> None:
    allowed_start_end = string.ascii_letters + string.digits
    allowed_middle_regex = string.ascii_letters + string.digits + r"\-\. _"
    min_length = 2

    error_code = "WRONG_NAME"
    error_symbols = ""

    if len(value) < min_length:
        raise AdcmEx(code=error_code, msg="Name is too short")

    if value[0] not in allowed_start_end:
        error_symbols += value[0]

    if len(value) >= 3:
        error_symbols += re.sub(rf"[{allowed_middle_regex}]+", "", value[1:-1])

    if value[-1] not in allowed_start_end:
        error_symbols += value[-1]

    if error_symbols:
        raise AdcmEx(code=error_code, msg=f"Incorrect symbol(s): `{error_symbols}`")
