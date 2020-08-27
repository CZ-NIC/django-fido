"""Test `django_fido.models`."""
import base64
import json

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase
from fido2.cose import ES256
from fido2.ctap2 import AttestationObject, AuthenticatorData

from django_fido.constants import AuthLevel, AuthVulnerability
from django_fido.models import Authenticator, AuthenticatorMetadata, TransportsValidator

from .data import (ATTESTATION_OBJECT, ATTESTATION_OBJECT_AAGUID, ATTESTATION_OBJECT_U2F, ATTESTATION_OBJECT_U2F_NO_EXT,
                   CREDENTIAL_ID, DETAILED_METADATA, DETAILED_METADATA_ATTESTATION_KEYS,
                   DETAILED_METADATA_ATTESTATION_KEYS_NO_EXT, DETAILED_METADATA_WRONG_CERT)


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


class TestAuthenticatorDatabase(TestCase):
    """Unittests for Authenticator methods that need database."""

    def test_metadata_no_identification(self):
        authenticator = Authenticator(attestation_data=ATTESTATION_OBJECT)
        self.assertIsNone(authenticator.metadata)

    def test_metadata_aaguid(self):
        metadata = AuthenticatorMetadata.objects.create(identifier='95442b2e-f15e-4def-b270-efb106facb4e',
                                                        detailed_metadata_entry=json.dumps(DETAILED_METADATA))
        authenticator = Authenticator(attestation_data=ATTESTATION_OBJECT_AAGUID)
        self.assertEqual(authenticator.metadata, metadata)

    def test_metadata_aaguid_wrong_cert(self):
        AuthenticatorMetadata.objects.create(
            identifier='95442b2e-f15e-4def-b270-efb106facb4e',
            detailed_metadata_entry=json.dumps(DETAILED_METADATA_WRONG_CERT))
        authenticator = Authenticator(attestation_data=ATTESTATION_OBJECT_AAGUID)
        self.assertIsNone(authenticator.metadata)

    def test_metadata_aaguid_no_match(self):
        authenticator = Authenticator(attestation_data=ATTESTATION_OBJECT_AAGUID)
        self.assertIsNone(authenticator.metadata)

    def test_metadata_u2f_no_extension(self):
        metadata = AuthenticatorMetadata.objects.create(
            identifier="['ed5bdb96011e3d457d858af39e30ac57c5ac95e6']",
            detailed_metadata_entry=json.dumps(DETAILED_METADATA_ATTESTATION_KEYS_NO_EXT))
        authenticator = Authenticator(attestation_data=ATTESTATION_OBJECT_U2F_NO_EXT)
        self.assertEqual(authenticator.metadata, metadata)

    def test_metadata_attestation_keys(self):
        metadata = AuthenticatorMetadata.objects.create(
            identifier="['3be6d2c06ff2e7b07c9d9e28c020b00d07c815c8']",
            detailed_metadata_entry=json.dumps(DETAILED_METADATA_ATTESTATION_KEYS))
        authenticator = Authenticator(attestation_data=ATTESTATION_OBJECT_U2F)
        self.assertEqual(authenticator.metadata, metadata)

    def test_metadata_attestation_keys_no_match(self):
        authenticator = Authenticator(attestation_data=ATTESTATION_OBJECT_U2F)
        self.assertIsNone(authenticator.metadata)


class TestAuthenticatorMetadata(TestCase):
    """Unittests for AuthenticatorMetadata model."""

    def test_level_single(self):
        status = {'statusReports': [{'status': 'FIDO_CERTIFIED'}]}
        metadata = AuthenticatorMetadata.objects.create(identifier='95442b2e-f15e-4def-b270-efb106facb4e',
                                                        metadata_entry=json.dumps(status))
        self.assertEqual(metadata.level, AuthLevel.L0)

    def test_level_revoked(self):
        status = {'statusReports': [{'status': 'FIDO_CERTIFIED'}, {'status': 'REVOKED'}]}
        metadata = AuthenticatorMetadata.objects.create(identifier='95442b2e-f15e-4def-b270-efb106facb4e',
                                                        metadata_entry=json.dumps(status))
        self.assertEqual(metadata.level, AuthLevel.NONE)

    def test_level_empty(self):
        metadata = AuthenticatorMetadata.objects.create(identifier='95442b2e-f15e-4def-b270-efb106facb4e',
                                                        metadata_entry=json.dumps({'statusReports': []}))
        self.assertEqual(metadata.level, AuthLevel.NONE)

    def test_level_breach_fixed(self):
        status = {'statusReports': [{'status': 'FIDO_CERTIFIED'},
                                    {'status': 'USER_VERIFICATION_BYPASS'},
                                    {'status': 'UPDATE_AVAILABLE'}]}
        metadata = AuthenticatorMetadata.objects.create(identifier='95442b2e-f15e-4def-b270-efb106facb4e',
                                                        metadata_entry=json.dumps(status))
        self.assertEqual(metadata.level, AuthLevel.L0)

    def test_level_breach_unfixed(self):
        status = {'statusReports': [{'status': 'FIDO_CERTIFIED_L1'},
                                    {'status': 'USER_VERIFICATION_BYPASS'}]}
        metadata = AuthenticatorMetadata.objects.create(identifier='95442b2e-f15e-4def-b270-efb106facb4e',
                                                        metadata_entry=json.dumps(status))
        self.assertEqual(metadata.level, AuthLevel.L1)

    def test_vulnerabilities_none(self):
        status = {'statusReports': [{'status': 'FIDO_CERTIFIED'}]}
        metadata = AuthenticatorMetadata.objects.create(identifier='95442b2e-f15e-4def-b270-efb106facb4e',
                                                        metadata_entry=json.dumps(status))
        self.assertEqual(metadata.vulnerabilities, [])

    def test_vulnerabilities_single(self):
        status = {'statusReports': [{'status': 'FIDO_CERTIFIED'},
                                    {'status': 'USER_VERIFICATION_BYPASS'}]}
        metadata = AuthenticatorMetadata.objects.create(identifier='95442b2e-f15e-4def-b270-efb106facb4e',
                                                        metadata_entry=json.dumps(status))
        self.assertEqual(metadata.vulnerabilities, [AuthVulnerability.USER_BYPASS])

    def test_vulnerabilities_multiple(self):
        status = {'statusReports': [{'status': 'FIDO_CERTIFIED'},
                                    {'status': 'ATTESTATION_KEY_COMPROMISE'},
                                    {'status': 'USER_VERIFICATION_BYPASS'}]}
        metadata = AuthenticatorMetadata.objects.create(identifier='95442b2e-f15e-4def-b270-efb106facb4e',
                                                        metadata_entry=json.dumps(status))
        self.assertEqual(metadata.vulnerabilities, [AuthVulnerability.USER_BYPASS,
                                                    AuthVulnerability.ATTESTATION_COMPROMISE])

    def test_is_update_available_none(self):
        status = {'statusReports': [{'status': 'FIDO_CERTIFIED'},
                                    {'status': 'ATTESTATION_KEY_COMPROMISE'},
                                    {'status': 'USER_VERIFICATION_BYPASS'}]}
        metadata = AuthenticatorMetadata.objects.create(identifier='95442b2e-f15e-4def-b270-efb106facb4e',
                                                        metadata_entry=json.dumps(status))
        self.assertFalse(metadata.is_update_available)

    def test_is_update_available_available(self):
        status = {'statusReports': [{'status': 'FIDO_CERTIFIED'},
                                    {'status': 'ATTESTATION_KEY_COMPROMISE'},
                                    {'status': 'UPDATE_AVAILABLE'},
                                    {'status': 'USER_VERIFICATION_BYPASS'}]}
        metadata = AuthenticatorMetadata.objects.create(identifier='95442b2e-f15e-4def-b270-efb106facb4e',
                                                        metadata_entry=json.dumps(status))
        self.assertTrue(metadata.is_update_available)
