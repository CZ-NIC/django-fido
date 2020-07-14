"""Test `django_fido.forms` module."""
import base64

from django.test import SimpleTestCase
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData

from django_fido.forms import Fido2AuthenticationForm, Fido2RegistrationForm

from .data import ATTESTATION_OBJECT


class TestFido2RegistrationForm(SimpleTestCase):
    def test_valid(self):
        # Test form with valid client data and attestation
        form = Fido2RegistrationForm({'client_data': 'eyJjaGFsbGVuZ2UiOiAiR2F6cGFjaG8hIn0=',
                                      'attestation': ATTESTATION_OBJECT})

        self.assertTrue(form.is_valid())
        cleaned_data = {'client_data': ClientData(b'{"challenge": "Gazpacho!"}'),
                        'attestation': AttestationObject(base64.b64decode(ATTESTATION_OBJECT)),
                        'label': ''}
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_valid_label(self):
        # Test form with valid client data and attestation
        form = Fido2RegistrationForm({'client_data': 'eyJjaGFsbGVuZ2UiOiAiR2F6cGFjaG8hIn0=',
                                      'attestation': ATTESTATION_OBJECT, 'label': 'My label'})

        self.assertTrue(form.is_valid())
        cleaned_data = {'client_data': ClientData(b'{"challenge": "Gazpacho!"}'),
                        'attestation': AttestationObject(base64.b64decode(ATTESTATION_OBJECT)),
                        'label': 'My label'}
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


AUTHENTICATOR_DATA = 'ACH1/AuFzSLmBiO819HKSJSJCSSbR3brUVFU5XtmrhIBAAAAHQ=='


class TestFido2AuthenticationForm(SimpleTestCase):
    def test_clean_client_data(self):
        form = Fido2AuthenticationForm({'client_data': 'eyJjaGFsbGVuZ2UiOiAiR2F6cGFjaG8hIn0=', 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertTrue(form.is_valid())
        cleaned_data = {
            'credential_id': b'\0', 'client_data': ClientData(b'{"challenge": "Gazpacho!"}'),
            'authenticator_data': AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)), 'signature': b'\0'}
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_clean_client_data_empty(self):
        form = Fido2AuthenticationForm({'client_data': '', 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'client_data': ["Operation wasn't completed."]})

    def test_clean_client_data_invalid(self):
        form = Fido2AuthenticationForm({'client_data': 'A', 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'client_data': ['FIDO 2 response is malformed.']})

    def test_clean_credential_id(self):
        form = Fido2AuthenticationForm({'client_data': 'e30=', 'credential_id': 'GAZPACHO',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertTrue(form.is_valid())
        cleaned_data = {
            'credential_id': base64.b64decode('GAZPACHO'), 'client_data': ClientData(b'{}'),
            'authenticator_data': AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)), 'signature': b'\0'}
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_clean_credential_id_empty(self):
        form = Fido2AuthenticationForm({'client_data': 'e30=', 'credential_id': '',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'credential_id': ["Operation wasn't completed."]})

    def test_clean_credential_id_invalid(self):
        form = Fido2AuthenticationForm({'client_data': 'e30=', 'credential_id': 'A',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'credential_id': ['FIDO 2 response is malformed.']})

    def test_clean_authenticator_data(self):
        form = Fido2AuthenticationForm({'client_data': 'e30=', 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertTrue(form.is_valid())
        cleaned_data = {
            'credential_id': b'\0', 'client_data': ClientData(b'{}'),
            'authenticator_data': AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)), 'signature': b'\0'}
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_clean_authenticator_data_empty(self):
        form = Fido2AuthenticationForm({'client_data': 'e30=', 'credential_id': 'AA==',
                                        'authenticator_data': '', 'signature': 'AA=='})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'authenticator_data': ["Operation wasn't completed."]})

    def test_clean_authenticator_data_invalid(self):
        form = Fido2AuthenticationForm({'client_data': 'e30=', 'credential_id': 'AA==',
                                        'authenticator_data': 'A', 'signature': 'AA=='})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'authenticator_data': ['FIDO 2 response is malformed.']})

    def test_clean_signature(self):
        form = Fido2AuthenticationForm({'client_data': 'e30=', 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'GAZPACHO'})

        self.assertTrue(form.is_valid())
        cleaned_data = {
            'credential_id': b'\0', 'client_data': ClientData(b'{}'),
            'authenticator_data': AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
            'signature': base64.b64decode('GAZPACHO')}
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_clean_signature_empty(self):
        form = Fido2AuthenticationForm({'client_data': 'e30=', 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': ''})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'signature': ["Operation wasn't completed."]})

    def test_clean_signature_invalid(self):
        form = Fido2AuthenticationForm({'client_data': 'e30=', 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'A'})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'signature': ['FIDO 2 response is malformed.']})
