"""Test `django_fido.models`."""
from __future__ import unicode_literals

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase
from mock import sentinel

from django_fido.models import TransportsValidator, U2fDevice


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


class TestU2fDevice(SimpleTestCase):
    """Test `U2fDevice` model."""

    # serialized, deserialized pairs
    transport_values = (
        (None, []),
        ('usb', ['usb']),
        ('bt,ble', ['bt', 'ble']),
    )

    def test_transports_getter(self):
        for raw, full in self.transport_values:
            u2f_key = U2fDevice(raw_transports=raw)
            self.assertEqual(u2f_key.transports, full)

    def test_transports_setter(self):
        for raw, full in self.transport_values:
            u2f_key = U2fDevice()
            u2f_key.transports = full
            self.assertEqual(u2f_key.raw_transports, raw)

    # base64 encoded, decoded pairs
    attestation_values = (
        (None, None),
        ('UmltbWVyJ3Mgc2lsdmVyIHN3aW1taW5nIGNlcnRpZmljYXRl', b"Rimmer's silver swimming certificate"),
    )

    def test_raw_attestation_getter(self):
        for encoded, decoded in self.attestation_values:
            u2f_key = U2fDevice(attestation=encoded)
            self.assertEqual(u2f_key.raw_attestation, decoded)

    def test_raw_attestation_setter(self):
        for encoded, decoded in self.attestation_values:
            u2f_key = U2fDevice()
            u2f_key.raw_attestation = decoded
            self.assertEqual(u2f_key.attestation, encoded)

    def test_get_registered_key(self):
        u2f_key = U2fDevice(key_handle=sentinel.key_handle, app_id=sentinel.app_id, version=sentinel.version,
                            raw_transports='usb,nfs', public_key=sentinel.public_key)
        retgistered_key = {'keyHandle': sentinel.key_handle,
                           'publicKey': sentinel.public_key,
                           'appId': sentinel.app_id,
                           'version': sentinel.version,
                           'transports': ['usb', 'nfs']}
        self.assertEqual(u2f_key.get_registered_key(), retgistered_key)
