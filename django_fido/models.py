"""Models for storing keys."""
import base64
import json
import warnings
from binascii import b2a_hex
from typing import List, Optional, cast
from uuid import UUID

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ExtensionNotFound, SubjectKeyIdentifier, load_der_x509_certificate
from cryptography.x509.oid import ExtensionOID
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.deconstruct import deconstructible
from django.utils.encoding import force_text
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from fido2.ctap2 import AttestationObject, AttestedCredentialData
from OpenSSL import crypto

from django_fido.constants import NULL_AAGUID, PEM_CERT_TEMPLATE, AuthLevel, AuthVulnerability

# Deprecated, kept for migrations
# https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-javascript-api-v1.2-ps-20170411.html#u2f-transports
TRANSPORT_CHOICES = (
    ('bt', _('Bluetooth Classic (Bluetooth BR/EDR)')),
    ('ble', _('Bluetooth Low Energy (Bluetooth Smart)')),
    ('nfc', _('Near-Field Communications')),
    ('usb', _('USB HID')),
    ('usb-internal', _('Non-removable USB HID')),
)


@deconstructible
class TransportsValidator(object):
    """Validator for comma separated transport values.

    @ivar choices: List/tuple of available values.
    """

    choices = tuple(choice for choice, label in TRANSPORT_CHOICES)
    code = 'invalid_choice'
    message = _('Select a valid choice. %(value)s is not one of the available choices.')

    def __init__(self, choices=None, code=None, message=None):
        """Set custom `choices`, `code` or `message`."""
        warnings.warn("TransportsValidator is deprecated. It is kept only for migrations.", DeprecationWarning)
        if choices is not None:
            self.choices = choices
        if code is not None:
            self.code = code
        if message is not None:
            self.message = message

    def __call__(self, value):
        """Validate the input."""
        for chunk in force_text(value).split(','):
            if chunk not in self.choices:
                raise ValidationError(self.message, code=self.code, params={'value': chunk})


class Authenticator(models.Model):
    """Represents a registered FIDO2 authenticator.

    Autheticator fields, see https://www.w3.org/TR/webauthn/#sec-authenticator-data
     * credential_id_data - base64 encoded credential ID https://www.w3.org/TR/webauthn/#credential-id
       * This field should be used for readonly purposes only.
     * attestation_data - base64 encoded attestation object
     * counter
    """

    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='authenticators', on_delete=models.CASCADE)
    create_datetime = models.DateTimeField(auto_now_add=True)

    credential_id_data = models.TextField(unique=True)
    attestation_data = models.TextField()
    counter = models.BigIntegerField(default=0)
    label = models.TextField(max_length=255, blank=True)

    class Meta:
        unique_together = [['user', 'label']]

    @property
    def credential_id(self) -> bytes:
        """Return raw credential ID."""
        return base64.b64decode(self.credential_id_data)

    @property
    def credential(self) -> AttestedCredentialData:
        """Return AttestedCredentialData object."""
        return self.attestation.auth_data.credential_data

    @property
    def attestation(self) -> AttestationObject:
        """Return AttestationObject object."""
        return AttestationObject(base64.b64decode(self.attestation_data))

    @attestation.setter
    def attestation(self, value: AttestationObject):
        self.attestation_data = base64.b64encode(value).decode('utf-8')
        self.credential_id_data = base64.b64encode(value.auth_data.credential_data.credential_id).decode('utf-8')

    def _get_metadata(self) -> Optional['AuthenticatorMetadata']:
        """Get the appropriate metadata."""
        # First test the presence of aaguid - FIDO 2
        if self.attestation.auth_data.credential_data.aaguid != NULL_AAGUID:
            identifier = str(UUID(b2a_hex(self.credential.aaguid).decode()))
            try:
                return AuthenticatorMetadata.objects.get(identifier=identifier)
            except AuthenticatorMetadata.DoesNotExist:
                return None
        else:
            # FIXME: Add handling for UAF devices with AAID
            # Get the certificate FIDO U2F
            if 'x5c' in self.attestation.att_statement:
                cert = self.attestation.att_statement['x5c'][0]
                certificate = load_der_x509_certificate(cert, default_backend())
            else:
                # ECDSAA attestation or self attestation?
                return None
            try:
                extension = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                subject_identifier = cast(SubjectKeyIdentifier, extension.value)
            except ExtensionNotFound:
                subject_identifier = SubjectKeyIdentifier.from_public_key(certificate.public_key())
            identifier = b2a_hex(subject_identifier.digest).decode()
            # Key identifiers are stored as lists...
            try:
                return AuthenticatorMetadata.objects.get(identifier__contains=identifier)
            except AuthenticatorMetadata.DoesNotExist:
                return None

    @cached_property
    def metadata(self) -> Optional['AuthenticatorMetadata']:
        """Verify and return the appropriate metada for this authenticator."""
        metadata = self._get_metadata()
        if metadata is not None and 'x5c' in self.attestation.att_statement:
            # Take the device certificate and try to validate against all certs in MDS
            device_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, self.attestation.att_statement['x5c'][0])
            root_certs = json.loads(metadata.detailed_metadata_entry)['attestationRootCertificates']
            store = crypto.X509Store()
            for root_cert in root_certs:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, PEM_CERT_TEMPLATE.format(root_cert))
                store.add_cert(cert)
            if len(self.attestation.att_statement['x5c']) > 1:
                for interm_cert in self.attestation.att_statement['x5c'][1:]:
                    store.add_cert(crypto.load_certificate(crypto.FILETYPE_ASN1, interm_cert))
            store_ctx = crypto.X509StoreContext(store, device_cert)
            try:
                store_ctx.verify_certificate()
            except crypto.X509StoreContextError:
                # The device certificate cannot be verified using the MDS certificate, do not trust the metadata
                return None
        return metadata


class AuthenticatorMetadata(models.Model):
    """Stores information from metadata service."""

    url = models.URLField(unique=True)
    identifier = models.TextField(unique=True)
    metadata_entry = models.TextField()
    detailed_metadata_entry = models.TextField()

    @cached_property
    def level(self) -> AuthLevel:
        """Return last valid certification level."""
        decoded = json.loads(self.metadata_entry)
        # The last status should be valid
        for status in reversed(decoded['statusReports']):
            # Is it directly a level?
            if status['status'] in tuple(AuthLevel):
                return AuthLevel(status['status'])
            elif status['status'] == 'REVOKED':
                return AuthLevel.NONE
        return AuthLevel.NONE

    @cached_property
    def vulnerabilities(self) -> List[AuthVulnerability]:
        """Return a list of reported vulnerabilities."""
        decoded = json.loads(self.metadata_entry)
        vulnerabilities = tuple(AuthVulnerability)
        return [AuthVulnerability(s['status']) for s in reversed(decoded['statusReports'])
                if s['status'] in vulnerabilities]

    @cached_property
    def is_update_available(self) -> bool:
        """Return whether an update is available."""
        decoded = json.loads(self.metadata_entry)
        return 'UPDATE_AVAILABLE' in [status['status'] for status in decoded['statusReports']]
