"""Unittests for download_authenticator_metadata."""
from __future__ import unicode_literals

import json
import os
from base64 import urlsafe_b64encode
from io import StringIO
from unittest.mock import patch

import responses
from django.core.management import CommandError, call_command
from django.test import SimpleTestCase, TestCase, override_settings
from requests.exceptions import RequestException

from django_fido.management.commands.download_authenticator_metadata import _get_metadata
from django_fido.models import AuthenticatorMetadata

DIR_PATH = os.path.join(os.path.dirname(__file__), 'data', 'mds')


@override_settings(DJANGO_FIDO_METADATA_SERVICE={'ACCESS_TOKEN': 'secret_token'})
class TestGetMetadata(SimpleTestCase):
    """Unittests for get_metadata command."""

    def get_file_content(self, path):
        """Return file content."""
        with open(path) as f:
            content = f.read()
        return content.strip().encode()

    def test_error_response(self):
        with responses.RequestsMock() as rsps:
            with self.assertRaisesMessage(CommandError, 'MDS response error.'):
                rsps.add(responses.GET, 'https://mds2.fidoalliance.org/', body=RequestException('Some error'))
                _get_metadata()

    def test_malformed_response(self):
        with responses.RequestsMock() as rsps:
            with self.assertRaisesMessage(CommandError, 'MDS response malformed.'):
                rsps.add(responses.GET, 'https://mds2.fidoalliance.org/', body='')
                _get_metadata()

    def test_ok_response(self):
        content = self.get_file_content(os.path.join(DIR_PATH, 'correct.txt'))
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, 'https://mds2.fidoalliance.org/', body=content)
            metadata = _get_metadata()
        self.assertEqual(set(metadata.keys()), {'entries', 'nextUpdate', 'no', 'legalHeader'})

    def test_bad_signature_response(self):
        content = self.get_file_content(os.path.join(DIR_PATH, 'bad.txt'))
        with responses.RequestsMock() as rsps:
            with self.assertRaisesMessage(CommandError, 'Could not verify MDS signature.'):
                rsps.add(responses.GET, 'https://mds2.fidoalliance.org/', body=content)
                _get_metadata()

    def test_default_url(self):
        content = self.get_file_content(os.path.join(DIR_PATH, 'correct.txt'))
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, 'https://mds2.fidoalliance.org/', body=content)
            _get_metadata()

    def test_custom_url(self):
        content = self.get_file_content(os.path.join(DIR_PATH, 'correct.txt'))
        with override_settings(DJANGO_FIDO_METADATA_SERVICE={'ACCESS_TOKEN': 'secret_token',
                                                             'URL': 'https://example.com'}):
            with responses.RequestsMock() as rsps:
                rsps.add(responses.GET, 'https://example.com', body=content)
                _get_metadata()

    def test_malformed_key(self):
        token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJhYWFhYWFhIl19.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikp' \
                'vaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.Dvmv1EMeu-pAqJdJAIXKef6M_Kx2Dn2qCLZyBF63f3RcI1ddDCXADlLmwvMjCX7u' \
                'V1R5AbLMf_rLxUlGZZnXvg'.encode()
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, 'https://mds2.fidoalliance.org/', body=token)
            with self.assertRaisesMessage(CommandError, 'Could not read the key.'):
                _get_metadata()


@override_settings(DJANGO_FIDO_METADATA_SERVICE={'ACCESS_TOKEN': 'secret_token'})
class TestDownloadAuthenticatorMetadata(TestCase):
    """Unittests for download_authenticator_metadata management command."""

    def test_not_configured(self):
        with self.assertRaisesMessage(CommandError, 'access_token setting must be specified for this command to work.'):
            with override_settings(DJANGO_FIDO_METADATA_SERVICE=None):
                call_command('download_authenticator_metadata')

    @patch('django_fido.management.commands.download_authenticator_metadata._get_metadata')
    def test_empty_list(self, get_metada_patch):
        get_metada_patch.return_value = {'entries': []}
        call_command('download_authenticator_metadata')
        self.assertFalse(AuthenticatorMetadata.objects.all().exists())

    @patch('django_fido.management.commands.download_authenticator_metadata._get_metadata')
    def test_aaid(self, get_metada_patch):
        entry = {'aaid': '1234#5678', 'url': 'https://example.com/1234abcd'}
        get_metada_patch.return_value = {'entries': [entry]}
        payload = {
            "description": "FIDO Alliance Sample UAF Authenticator",
            "aaid": "1234#5678",
            "authenticatorVersion": 2,
            "upv": [
                {"major": 1, "minor": 0},
                {"major": 1, "minor": 1}
            ],
            "assertionScheme": "UAFV1TLV",
            "authenticationAlgorithm": 1,
            "publicKeyAlgAndEncoding": 256,
            "attestationTypes": [15879],
            "userVerificationDetails": [
                [{
                    "userVerification": 2,
                    "baDesc": {
                        "FAR": 0.00002,
                        "maxRetries": 5,
                        "blockSlowdown": 30,
                        "maxReferenceDataSets": 5
                    }
                }]
            ],
            "keyProtection": 6,
            "isKeyRestricted": True,
            "matcherProtection": 2,
            "cryptoStrength": 128,
            "operatingEnv": "TEEs based on ARM TrustZone HW",
            "attachmentHint": 1,
            "isSecondFactorOnly": False,
            "tcDisplay": 5,
            "tcDisplayContentType": "image/png",
            "tcDisplayPNGCharacteristics": [{
                "width": 320,
                "height": 480,
                "bitDepth": 16,
                "colorType": 2,
                "compression": 0,
                "filter": 0,
                "interlace": 0
            }],
            "attestationRootCertificates": [
                "MIICPTCCAeOgAwIBAgIJAOuexvU3Oy2wMAoGCCqGSM49BAMCMHsxIDAeBgNVBAMM"
                "F1NhbXBsZSBBdHRlc3RhdGlvbiBSb290MRYwFAYDVQQKDA1GSURPIEFsbGlhbmNl"
                "MREwDwYDVQQLDAhVQUYgVFdHLDESMBAGA1UEBwwJUGFsbyBBbHRvMQswCQYDVQQI"
                "DAJDQTELMAkGA1UEBhMCVVMwHhcNMTQwNjE4MTMzMzMyWhcNNDExMTAzMTMzMzMy"
                "WjB7MSAwHgYDVQQDDBdTYW1wbGUgQXR0ZXN0YXRpb24gUm9vdDEWMBQGA1UECgwN"
                "RklETyBBbGxpYW5jZTERMA8GA1UECwwIVUFGIFRXRywxEjAQBgNVBAcMCVBhbG8g"
                "QWx0bzELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZI"
                "zj0DAQcDQgAEH8hv2D0HXa59/BmpQ7RZehL/FMGzFd1QBg9vAUpOZ3ajnuQ94PR7"
                "aMzH33nUSBr8fHYDrqOBb58pxGqHJRyX/6NQME4wHQYDVR0OBBYEFPoHA3CLhxFb"
                "C0It7zE4w8hk5EJ/MB8GA1UdIwQYMBaAFPoHA3CLhxFbC0It7zE4w8hk5EJ/MAwG"
                "A1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ06QSXt9ihIbEKYKIjsPkri"
                "VdLIgtfsbDSu7ErJfzr4AiBqoYCZf0+zI55aQeAHjIzA9Xm63rruAxBZ9ps9z2XN"
                "lQ=="
             ]
        }
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, 'https://example.com/1234abcd',
                     body=urlsafe_b64encode(json.dumps(payload).encode()))
            call_command('download_authenticator_metadata')
        metadata = AuthenticatorMetadata.objects.get(identifier='1234#5678')
        self.assertJSONEqual(metadata.metadata_entry, entry)
        self.assertJSONEqual(metadata.detailed_metadata_entry, payload)

    @patch('django_fido.management.commands.download_authenticator_metadata._get_metadata')
    def test_aaid_update(self, get_metada_patch):
        AuthenticatorMetadata.objects.create(identifier='1234#5678')
        entry = {'aaid': '1234#5678', 'url': 'https://example.com/1234abcd'}
        get_metada_patch.return_value = {'entries': [entry]}
        payload = {
            "description": "FIDO Alliance Sample UAF Authenticator",
            "aaid": "1234#5678",
            "authenticatorVersion": 2,
            "upv": [
                {"major": 1, "minor": 0},
                {"major": 1, "minor": 1}
            ],
            "assertionScheme": "UAFV1TLV",
            "authenticationAlgorithm": 1,
            "publicKeyAlgAndEncoding": 256,
            "attestationTypes": [15879],
            "userVerificationDetails": [
                [{
                    "userVerification": 2,
                    "baDesc": {
                        "FAR": 0.00002,
                        "maxRetries": 5,
                        "blockSlowdown": 30,
                        "maxReferenceDataSets": 5
                    }
                }]
            ],
            "keyProtection": 6,
            "isKeyRestricted": True,
            "matcherProtection": 2,
            "cryptoStrength": 128,
            "operatingEnv": "TEEs based on ARM TrustZone HW",
            "attachmentHint": 1,
            "isSecondFactorOnly": False,
            "tcDisplay": 5,
            "tcDisplayContentType": "image/png",
            "tcDisplayPNGCharacteristics": [{
                "width": 320,
                "height": 480,
                "bitDepth": 16,
                "colorType": 2,
                "compression": 0,
                "filter": 0,
                "interlace": 0
            }],
            "attestationRootCertificates": [
                "MIICPTCCAeOgAwIBAgIJAOuexvU3Oy2wMAoGCCqGSM49BAMCMHsxIDAeBgNVBAMM"
                "F1NhbXBsZSBBdHRlc3RhdGlvbiBSb290MRYwFAYDVQQKDA1GSURPIEFsbGlhbmNl"
                "MREwDwYDVQQLDAhVQUYgVFdHLDESMBAGA1UEBwwJUGFsbyBBbHRvMQswCQYDVQQI"
                "DAJDQTELMAkGA1UEBhMCVVMwHhcNMTQwNjE4MTMzMzMyWhcNNDExMTAzMTMzMzMy"
                "WjB7MSAwHgYDVQQDDBdTYW1wbGUgQXR0ZXN0YXRpb24gUm9vdDEWMBQGA1UECgwN"
                "RklETyBBbGxpYW5jZTERMA8GA1UECwwIVUFGIFRXRywxEjAQBgNVBAcMCVBhbG8g"
                "QWx0bzELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZI"
                "zj0DAQcDQgAEH8hv2D0HXa59/BmpQ7RZehL/FMGzFd1QBg9vAUpOZ3ajnuQ94PR7"
                "aMzH33nUSBr8fHYDrqOBb58pxGqHJRyX/6NQME4wHQYDVR0OBBYEFPoHA3CLhxFb"
                "C0It7zE4w8hk5EJ/MB8GA1UdIwQYMBaAFPoHA3CLhxFbC0It7zE4w8hk5EJ/MAwG"
                "A1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ06QSXt9ihIbEKYKIjsPkri"
                "VdLIgtfsbDSu7ErJfzr4AiBqoYCZf0+zI55aQeAHjIzA9Xm63rruAxBZ9ps9z2XN"
                "lQ=="
             ]
        }
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, 'https://example.com/1234abcd',
                     body=urlsafe_b64encode(json.dumps(payload).encode()))
            call_command('download_authenticator_metadata')
        metadata = AuthenticatorMetadata.objects.get(identifier='1234#5678')
        self.assertJSONEqual(metadata.metadata_entry, entry)
        self.assertJSONEqual(metadata.detailed_metadata_entry, payload)

    @patch('django_fido.management.commands.download_authenticator_metadata._get_metadata')
    def test_aaguid(self, get_metada_patch):
        entry = {'attestationCertificateKeyIdentifiers': ['7c0903708b87115b0b422def3138c3c864e44573'],
                 'url': 'https://example.com/abcd'}
        get_metada_patch.return_value = {'entries': [entry]}
        payload = {
            "description": "FIDO Alliance Sample U2F Authenticator",
            "attestationCertificateKeyIdentifiers": ["7c0903708b87115b0b422def3138c3c864e44573"],
            "protocolFamily": "u2f",
            "authenticatorVersion": 2,
            "upv": [{"major": 1, "minor": 0}],
            "assertionScheme": "U2FV1BIN",
            "authenticationAlgorithm": 1,
            "publicKeyAlgAndEncoding": 256,
            "attestationTypes": [15879],
            "userVerificationDetails": [[{"userVerification": 1}]],
            "keyProtection": 10,
            "matcherProtection": 4,
            "cryptoStrength": 128,
            "operatingEnv": "Secure Element (SE)",
            "attachmentHint": 2,
            "isSecondFactorOnly": True,
            "tcDisplay": 0,
            "attestationRootCertificates": [
                "MIICPTCCAeOgAwIBAgIJAOuexvU3Oy2wMAoGCCqGSM49BAMCMHsxIDAeBgNVBAMM"
                "F1NhbXBsZSBBdHRlc3RhdGlvbiBSb290MRYwFAYDVQQKDA1GSURPIEFsbGlhbmNl"
                "MREwDwYDVQQLDAhVQUYgVFdHLDESMBAGA1UEBwwJUGFsbyBBbHRvMQswCQYDVQQI"
                "DAJDQTELMAkGA1UEBhMCVVMwHhcNMTQwNjE4MTMzMzMyWhcNNDExMTAzMTMzMzMy"
                "WjB7MSAwHgYDVQQDDBdTYW1wbGUgQXR0ZXN0YXRpb24gUm9vdDEWMBQGA1UECgwN"
                "RklETyBBbGxpYW5jZTERMA8GA1UECwwIVUFGIFRXRywxEjAQBgNVBAcMCVBhbG8g"
                "QWx0bzELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZI"
                "zj0DAQcDQgAEH8hv2D0HXa59/BmpQ7RZehL/FMGzFd1QBg9vAUpOZ3ajnuQ94PR7"
                "aMzH33nUSBr8fHYDrqOBb58pxGqHJRyX/6NQME4wHQYDVR0OBBYEFPoHA3CLhxFb"
                "C0It7zE4w8hk5EJ/MB8GA1UdIwQYMBaAFPoHA3CLhxFbC0It7zE4w8hk5EJ/MAwG"
                "A1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ06QSXt9ihIbEKYKIjsPkri"
                "VdLIgtfsbDSu7ErJfzr4AiBqoYCZf0+zI55aQeAHjIzA9Xm63rruAxBZ9ps9z2XN"
                "lQ=="
                ]
            }
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, 'https://example.com/abcd',
                     body=urlsafe_b64encode(json.dumps(payload).encode()))
            call_command('download_authenticator_metadata')
        metadata = AuthenticatorMetadata.objects.get(identifier__contains='7c0903708b87115b0b422def3138c3c864e44573')
        self.assertJSONEqual(metadata.metadata_entry, entry)
        self.assertJSONEqual(metadata.detailed_metadata_entry, payload)

    @patch('django_fido.management.commands.download_authenticator_metadata._get_metadata')
    def test_key_identifiers(self, get_metada_patch):
        entry = {'aaguid': '7c0903708b87115b0b422def3138c3c864e44573',
                 'url': 'https://example.com/7c0903708b87115b0b422def3138c3c864e44573'}
        get_metada_patch.return_value = {'entries': [entry]}
        payload = {
            "description": "FIDO Alliance Sample U2F Authenticator",
            "attestationCertificateKeyIdentifiers": ["7c0903708b87115b0b422def3138c3c864e44573"],
            "protocolFamily": "u2f",
            "authenticatorVersion": 2,
            "upv": [{"major": 1, "minor": 0}],
            "assertionScheme": "U2FV1BIN",
            "authenticationAlgorithm": 1,
            "publicKeyAlgAndEncoding": 256,
            "attestationTypes": [15879],
            "userVerificationDetails": [[{"userVerification": 1}]],
            "keyProtection": 10,
            "matcherProtection": 4,
            "cryptoStrength": 128,
            "operatingEnv": "Secure Element (SE)",
            "attachmentHint": 2,
            "isSecondFactorOnly": True,
            "tcDisplay": 0,
            "attestationRootCertificates": [
                "MIICPTCCAeOgAwIBAgIJAOuexvU3Oy2wMAoGCCqGSM49BAMCMHsxIDAeBgNVBAMM"
                "F1NhbXBsZSBBdHRlc3RhdGlvbiBSb290MRYwFAYDVQQKDA1GSURPIEFsbGlhbmNl"
                "MREwDwYDVQQLDAhVQUYgVFdHLDESMBAGA1UEBwwJUGFsbyBBbHRvMQswCQYDVQQI"
                "DAJDQTELMAkGA1UEBhMCVVMwHhcNMTQwNjE4MTMzMzMyWhcNNDExMTAzMTMzMzMy"
                "WjB7MSAwHgYDVQQDDBdTYW1wbGUgQXR0ZXN0YXRpb24gUm9vdDEWMBQGA1UECgwN"
                "RklETyBBbGxpYW5jZTERMA8GA1UECwwIVUFGIFRXRywxEjAQBgNVBAcMCVBhbG8g"
                "QWx0bzELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZI"
                "zj0DAQcDQgAEH8hv2D0HXa59/BmpQ7RZehL/FMGzFd1QBg9vAUpOZ3ajnuQ94PR7"
                "aMzH33nUSBr8fHYDrqOBb58pxGqHJRyX/6NQME4wHQYDVR0OBBYEFPoHA3CLhxFb"
                "C0It7zE4w8hk5EJ/MB8GA1UdIwQYMBaAFPoHA3CLhxFbC0It7zE4w8hk5EJ/MAwG"
                "A1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ06QSXt9ihIbEKYKIjsPkri"
                "VdLIgtfsbDSu7ErJfzr4AiBqoYCZf0+zI55aQeAHjIzA9Xm63rruAxBZ9ps9z2XN"
                "lQ=="
            ],
        }
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, 'https://example.com/7c0903708b87115b0b422def3138c3c864e44573',
                     body=urlsafe_b64encode(json.dumps(payload).encode()))
            call_command('download_authenticator_metadata')
        metadata = AuthenticatorMetadata.objects.get(identifier='7c0903708b87115b0b422def3138c3c864e44573')
        self.assertJSONEqual(metadata.metadata_entry, entry)
        self.assertJSONEqual(metadata.detailed_metadata_entry, payload)

    @patch('django_fido.management.commands.download_authenticator_metadata._get_metadata')
    def test_key_unknown(self, get_metada_patch):
        output = StringIO()
        get_metada_patch.return_value = {'entries': [{}]}
        call_command('download_authenticator_metadata', stderr=output)
        self.assertEqual('Cannot determine the identificator from metadata response.\n',
                         output.getvalue())
