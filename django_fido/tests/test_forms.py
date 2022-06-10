"""Test `django_fido.forms` module."""
import base64

from django.test import SimpleTestCase, override_settings
from fido2.webauthn import AttestationObject, AuthenticatorData, CollectedClientData

from django_fido.forms import Fido2AuthenticationForm, Fido2PasswordlessAuthenticationForm, Fido2RegistrationForm

from .data import ATTESTATION_OBJECT, REGISTRATION_CLIENT_DATA, USER_HANDLE, USER_HANDLE_B64


class TestFido2RegistrationForm(SimpleTestCase):
    def test_valid(self):
        # Test form with valid client data and attestation
        form = Fido2RegistrationForm({'client_data': REGISTRATION_CLIENT_DATA, 'user_handle': USER_HANDLE_B64,
                                      'attestation': ATTESTATION_OBJECT})

        self.assertTrue(form.is_valid())
        cleaned_data = {
            'client_data': CollectedClientData(b'{"type": "webauthn.create", "challenge": "Gazpacho!", '
                                               b'"origin": "https://testserver"}'),
            'attestation': AttestationObject(base64.b64decode(ATTESTATION_OBJECT)),
            'user_handle': None, 'label': '',
        }
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_valid_label(self):
        # Test form with valid client data and attestation
        form = Fido2RegistrationForm({'client_data': REGISTRATION_CLIENT_DATA, 'attestation': ATTESTATION_OBJECT,
                                      'label': 'My label', 'user_handle': USER_HANDLE_B64})

        self.assertTrue(form.is_valid())
        cleaned_data = {
            'client_data': CollectedClientData(b'{"type": "webauthn.create", "challenge": "Gazpacho!", '
                                               b'"origin": "https://testserver"}'),
            'attestation': AttestationObject(base64.b64decode(ATTESTATION_OBJECT)),
            'user_handle': None, 'label': 'My label',
        }
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_clean_client_data_empty(self):
        form = Fido2RegistrationForm({'client_data': '', 'attestation': ATTESTATION_OBJECT,
                                      'user_handle': USER_HANDLE_B64})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'client_data': ["Operation wasn't completed."]})

    def test_clean_client_data_invalid(self):
        form = Fido2RegistrationForm({'client_data': 'A', 'attestation': ATTESTATION_OBJECT,
                                      'user_handle': USER_HANDLE_B64})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'client_data': ['FIDO 2 response is malformed.']})

    def test_clean_attestation_empty(self):
        form = Fido2RegistrationForm({'client_data': REGISTRATION_CLIENT_DATA, 'attestation': '',
                                      'user_handle': USER_HANDLE_B64})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'attestation': ["Operation wasn't completed."]})

    def test_clean_attestation_invalid(self):
        form = Fido2RegistrationForm({'client_data': REGISTRATION_CLIENT_DATA, 'attestation': 'A',
                                      'user_handle': USER_HANDLE_B64})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'attestation': ['FIDO 2 response is malformed.']})


@override_settings(DJANGO_FIDO_RESIDENT_KEY=True)
class TestFido2RegistrationFormWithResidentKey(SimpleTestCase):
    def test_valid(self):
        # Test form with valid client data and attestation
        form = Fido2RegistrationForm({'client_data': REGISTRATION_CLIENT_DATA, 'user_handle': USER_HANDLE_B64,
                                      'attestation': ATTESTATION_OBJECT})

        self.assertTrue(form.is_valid())
        cleaned_data = {'client_data': CollectedClientData(b'{"type": "webauthn.create", "challenge": "Gazpacho!", '
                                                           b'"origin": "https://testserver"}'),
                        'attestation': AttestationObject(base64.b64decode(ATTESTATION_OBJECT)),
                        'user_handle': USER_HANDLE, 'label': ''}
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_clean_user_handle_invalid(self):
        form = Fido2RegistrationForm({'client_data': REGISTRATION_CLIENT_DATA, 'attestation': ATTESTATION_OBJECT,
                                      'user_handle': ''})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'user_handle': ['This field is required.']})


AUTHENTICATOR_DATA = 'ACH1/AuFzSLmBiO819HKSJSJCSSbR3brUVFU5XtmrhIBAAAAHQ=='


class TestFido2AuthenticationForm(SimpleTestCase):
    def test_clean_client_data(self):
        form = Fido2AuthenticationForm({'client_data': REGISTRATION_CLIENT_DATA, 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertTrue(form.is_valid())
        cleaned_data = {
            'credential_id': b'\0',
            'client_data': CollectedClientData(b'{"type": "webauthn.create", "challenge": "Gazpacho!", '
                                               b'"origin": "https://testserver"}'),
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
        form = Fido2AuthenticationForm({'client_data': REGISTRATION_CLIENT_DATA, 'credential_id': 'GAZPACHO',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertTrue(form.is_valid())
        cleaned_data = {
            'credential_id': base64.b64decode('GAZPACHO'),
            'client_data': CollectedClientData(b'{"type": "webauthn.create", "challenge": "Gazpacho!", '
                                               b'"origin": "https://testserver"}'),
            'authenticator_data': AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)), 'signature': b'\0'}
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_clean_credential_id_empty(self):
        form = Fido2AuthenticationForm({'client_data': REGISTRATION_CLIENT_DATA, 'credential_id': '',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'credential_id': ["Operation wasn't completed."]})

    def test_clean_credential_id_invalid(self):
        form = Fido2AuthenticationForm({'client_data': REGISTRATION_CLIENT_DATA, 'credential_id': 'A',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'credential_id': ['FIDO 2 response is malformed.']})

    def test_clean_authenticator_data(self):
        form = Fido2AuthenticationForm({'client_data': REGISTRATION_CLIENT_DATA, 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'AA=='})

        self.assertTrue(form.is_valid())
        cleaned_data = {
            'credential_id': b'\0',
            'client_data': CollectedClientData(b'{"type": "webauthn.create", "challenge": "Gazpacho!", '
                                               b'"origin": "https://testserver"}'),
            'authenticator_data': AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)), 'signature': b'\0'}
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_clean_authenticator_data_empty(self):
        form = Fido2AuthenticationForm({'client_data': REGISTRATION_CLIENT_DATA, 'credential_id': 'AA==',
                                        'authenticator_data': '', 'signature': 'AA=='})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'authenticator_data': ["Operation wasn't completed."]})

    def test_clean_authenticator_data_invalid(self):
        form = Fido2AuthenticationForm({'client_data': REGISTRATION_CLIENT_DATA, 'credential_id': 'AA==',
                                        'authenticator_data': 'A', 'signature': 'AA=='})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'authenticator_data': ['FIDO 2 response is malformed.']})

    def test_clean_signature(self):
        form = Fido2AuthenticationForm({'client_data': REGISTRATION_CLIENT_DATA, 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'GAZPACHO'})

        self.assertTrue(form.is_valid())
        cleaned_data = {
            'credential_id': b'\0',
            'client_data': CollectedClientData(b'{"type": "webauthn.create", "challenge": "Gazpacho!", '
                                               b'"origin": "https://testserver"}'),
            'authenticator_data': AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
            'signature': base64.b64decode('GAZPACHO')}
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_clean_signature_empty(self):
        form = Fido2AuthenticationForm({'client_data': REGISTRATION_CLIENT_DATA, 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': ''})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'signature': ["Operation wasn't completed."]})

    def test_clean_signature_invalid(self):
        form = Fido2AuthenticationForm({'client_data': REGISTRATION_CLIENT_DATA, 'credential_id': 'AA==',
                                        'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'A'})

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'signature': ['FIDO 2 response is malformed.']})


class TestFido2PasswordlessAuthenticationForm(SimpleTestCase):
    def test_clean_user_handle(self):
        form = Fido2PasswordlessAuthenticationForm(
            {'client_data': REGISTRATION_CLIENT_DATA,
             'credential_id': 'AA==',
             'user_handle': USER_HANDLE_B64,
             'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'GAZPACHO'}
        )

        self.assertTrue(form.is_valid())
        cleaned_data = {
            'client_data': CollectedClientData(b'{"type": "webauthn.create", "challenge": "Gazpacho!", '
                                               b'"origin": "https://testserver"}'),
            'credential_id': b'\0', 'user_handle': USER_HANDLE,
            'authenticator_data': AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
            'signature': base64.b64decode('GAZPACHO')}
        self.assertEqual(form.cleaned_data, cleaned_data)

    def test_clean_user_handle_invalid(self):
        form = Fido2PasswordlessAuthenticationForm(
            {'client_data': REGISTRATION_CLIENT_DATA,
             'credential_id': 'AA==', 'user_handle': 'abc',
             'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'GAZPACHO'}
        )

        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors, {'user_handle': ['FIDO 2 response is malformed.']})
