"""Unittests for setting utilities."""
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from django_fido.settings import timeout_validator


class TestTimeoutValidator(SimpleTestCase):
    """Unittests for timeout_validator."""

    def test_timeout_validator(self):
        timeout_validator(123)
        timeout_validator(123.45)
        timeout_validator((123, 45))
        timeout_validator((123.45, 678.9))
        timeout_validator((123, 45.67))
        with self.assertRaisesRegex(ValidationError, r'Value .* must be a float, int or a tuple with 2 float .+'):
            timeout_validator('Hello world!')
        with self.assertRaisesRegex(ValidationError, r'Value .* must be a float, int or a tuple with 2 float .+'):
            timeout_validator([123])
        with self.assertRaisesRegex(ValidationError, r'Value .* must be a float, int or a tuple with 2 float .+'):
            timeout_validator({'hello': 'World!'})
        with self.assertRaisesRegex(ValidationError, r'Value .* must be a float, int or a tuple with 2 float .+'):
            timeout_validator((123,))
        with self.assertRaisesRegex(ValidationError, r'Value .* must be a float, int or a tuple with 2 float .+'):
            timeout_validator((1, 2, 3))
