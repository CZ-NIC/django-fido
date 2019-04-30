"""Test `django_fido.forms` module."""
from __future__ import unicode_literals

import base64

from django.test import SimpleTestCase
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject

from django_fido.forms import Fido2RegistrationForm, U2fResponseForm

from .data import ATTESTATION_OBJECT


class TestFido2RegistrationForm(SimpleTestCase):
    def test_valid(self):
        # Test form with valid client data and attestation
        form = Fido2RegistrationForm({'client_data': 'eyJjaGFsbGVuZ2UiOiAiR2F6cGFjaG8hIn0=',
                                      'attestation': ATTESTATION_OBJECT})

        self.assertTrue(form.is_valid())
        cleaned_data = {'client_data': ClientData(b'{"challenge": "Gazpacho!"}'),
                        'attestation': AttestationObject(base64.b64decode(ATTESTATION_OBJECT))}
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_clean_client_data_empty(self):
        form = Fido2RegistrationForm({'client_data': '', 'attestation': ATTESTATION_OBJECT})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'client_data': ["Operation wasn't completed."]})

    def test_clean_client_data_invalid(self):
        form = Fido2RegistrationForm({'client_data': 'A', 'attestation': ATTESTATION_OBJECT})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'client_data': ['FIDO 2 response is malformed.']})

    def test_clean_attestation_empty(self):
        form = Fido2RegistrationForm({'client_data': 'e30=', 'attestation': ''})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'attestation': ["Operation wasn't completed."]})

    def test_clean_attestation_invalid(self):
        form = Fido2RegistrationForm({'client_data': 'e30=', 'attestation': 'A'})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'attestation': ['FIDO 2 response is malformed.']})


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
