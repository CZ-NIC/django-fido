"""Test `django_fido.models`."""
from __future__ import unicode_literals

import base64

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase
from fido2.cose import ES256
from fido2.ctap2 import AttestationObject, AuthenticatorData

from django_fido.models import Authenticator, TransportsValidator

from .data import ATTESTATION_OBJECT, CREDENTIAL_ID


class TestTransportsValidator(SimpleTestCase):
    """Test `TransportsValidator`."""

    valid_values = (
        # Single values
        'bt', 'ble', 'nfc', 'usb', 'usb-internal',
        # Mutliple values
        'bt,ble', 'nfc,usb', 'bt,ble,nfc,usb,usb-internal',
    )

    def test_valid(self):
        validator = TransportsValidator()
        for value in self.valid_values:
            validator(value)

    # (input - invalid chunk) pairs
    invalid_values = (
        ('', ''),
        (' ', ' '),
        (',', ''),
        # Unknown value
        ('junk', 'junk'),
        # No extra spaces
        ('bt, ble', ' ble'),
        ('nfc ,usb', 'nfc '),
    )

    def test_invalid(self):
        validator = TransportsValidator()

        for value, invalid_chunk in self.invalid_values:
            with self.assertRaisesMessage(ValidationError, 'Select a valid choice.') as catcher:
                validator(value)
            self.assertEqual(catcher.exception.code, 'invalid_choice')
            self.assertEqual(catcher.exception.params, {'value': invalid_chunk})

    def test_custom_choices(self):
        validator = TransportsValidator(choices=['foo', 'bar'])

        validator('foo,bar')
        self.assertRaisesMessage(ValidationError, 'Select a valid choice.', validator, 'usb')

    def test_custom_code(self):
        validator = TransportsValidator(code='smeghead')

        with self.assertRaisesMessage(ValidationError, 'Select a valid choice.') as catcher:
            validator('rimmer')
        self.assertEqual(catcher.exception.code, 'smeghead')

    def test_custom_message(self):
        validator = TransportsValidator(message="You're a smeghead.")

        self.assertRaisesMessage(ValidationError, "You're a smeghead.", validator, 'rimmer')


class TestAuthenticator(SimpleTestCase):
    """Test `Authenticator` model."""

    def test_credential_id_getter(self):
        authenticator = Authenticator(credential_id_data='Q1JFREVOVElBTF9JRA==')

        self.assertEqual(authenticator.credential_id, b'CREDENTIAL_ID')

    def test_credential_getter(self):
        authenticator = Authenticator(attestation_data=ATTESTATION_OBJECT)

        self.assertEqual(authenticator.credential.aaguid, b'\0' * 16)
        self.assertEqual(authenticator.credential.credential_id, base64.b64decode(CREDENTIAL_ID))
        self.assertIsInstance(authenticator.credential.public_key, ES256)

    def test_attestation_getter(self):
        authenticator = Authenticator(attestation_data=ATTESTATION_OBJECT)

        self.assertEqual(authenticator.attestation.fmt, 'fido-u2f')
        self.assertIsInstance(authenticator.attestation.auth_data, AuthenticatorData)

    def test_attestation_setter(self):
        authenticator = Authenticator()

        authenticator.attestation = AttestationObject(base64.b64decode(ATTESTATION_OBJECT))

        self.assertEqual(authenticator.attestation_data, ATTESTATION_OBJECT)
        self.assertEqual(authenticator.credential_id_data, CREDENTIAL_ID)
