"""Test `django_fido.forms` module."""
from __future__ import unicode_literals

from django.test import SimpleTestCase

from django_fido.forms import U2fResponseForm


class TestU2fResponseForm(SimpleTestCase):
    """Test `U2fResponseForm` class."""

    def test_clean_u2f_response(self):
        form = U2fResponseForm({'u2f_response': '{"answer": 42}'})

        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data, {'u2f_response': {'answer': 42}})

    def test_clean_u2f_response_invalid(self):
        form = U2fResponseForm({'u2f_response': 'JUNK'})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'u2f_response': ['U2F response is malformed.']})
