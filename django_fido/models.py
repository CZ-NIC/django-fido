"""Models for storing keys."""

from __future__ import annotations

import base64
import json
import warnings
from binascii import b2a_hex
from datetime import date
from operator import methodcaller
from typing import cast
from uuid import UUID

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ExtensionNotFound, SubjectKeyIdentifier, load_der_x509_certificate
from cryptography.x509.oid import ExtensionOID
from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned, ValidationError
from django.db import models
from django.utils.deconstruct import deconstructible
from django.utils.encoding import force_str
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from fido2.webauthn import AttestationObject, AttestedCredentialData
from OpenSSL import crypto

from django_fido.constants import NULL_AAGUID, PEM_CERT_TEMPLATE, AuthLevel, AuthVulnerability

# Deprecated, kept for migrations
# https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-javascript-api-v1.2-ps-20170411.html#u2f-transports
TRANSPORT_CHOICES = (
    ("bt", _("Bluetooth Classic (Bluetooth BR/EDR)")),
    ("ble", _("Bluetooth Low Energy (Bluetooth Smart)")),
    ("nfc", _("Near-Field Communications")),
    ("usb", _("USB HID")),
    ("usb-internal", _("Non-removable USB HID")),
)


@deconstructible
class TransportsValidator:
    """Validator for comma separated transport values.

    @ivar choices: List/tuple of available values.
    """

    choices = tuple(choice for choice, label in TRANSPORT_CHOICES)
    code = "invalid_choice"
    message = _("Select a valid choice. %(value)s is not one of the available choices.")

    def __init__(self, choices=None, code=None, message=None):
        """Set custom `choices`, `code` or `message`."""
        warnings.warn(
            "TransportsValidator is deprecated. It is kept only for migrations.", DeprecationWarning, stacklevel=2
        )
        if choices is not None:
            self.choices = choices
        if code is not None:
            self.code = code
        if message is not None:
            self.message = message

    def __call__(self, value):
        """Validate the input."""
        for chunk in force_str(value).split(","):
            if chunk not in self.choices:
                raise ValidationError(self.message, code=self.code, params={"value": chunk})


class Authenticator(models.Model):
    """Represents a registered FIDO2 authenticator.

    Autheticator fields, see https://www.w3.org/TR/webauthn/#sec-authenticator-data
     * credential_id_data - base64 encoded credential ID https://www.w3.org/TR/webauthn/#credential-id
       * This field should be used for readonly purposes only.
     * attestation_data - base64 encoded attestation object
     * counter
    """

    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="authenticators", on_delete=models.CASCADE)
    user_handle = models.TextField(blank=True, unique=True, null=True)
    create_datetime = models.DateTimeField(auto_now_add=True)

    credential_id_data = models.TextField(unique=True)
    attestation_data = models.TextField()
    counter = models.BigIntegerField(default=0)
    label = models.TextField(max_length=255, blank=True)

    class Meta:
        unique_together = [["user", "label"]]

    @property
    def credential_id(self) -> bytes:
        """Return raw credential ID."""
        return base64.b64decode(self.credential_id_data)

    @property
    def credential(self) -> AttestedCredentialData | None:
        """Return AttestedCredentialData object."""
        return self.attestation.auth_data.credential_data

    @property
    def attestation(self) -> AttestationObject:
        """Return AttestationObject object."""
        return AttestationObject(base64.b64decode(self.attestation_data))

    @attestation.setter
    def attestation(self, value: AttestationObject):
        self.attestation_data = base64.b64encode(value).decode("utf-8")
        self.credential_id_data = base64.b64encode(
            cast(AttestedCredentialData, value.auth_data.credential_data).credential_id
        ).decode("utf-8")

    @cached_property
    def identifier(self) -> str | bytes | None:
        """Return key identifier."""
        if (
            hasattr(self.attestation.auth_data, "credential_data")
            and self.attestation.auth_data.credential_data is not None
            and self.attestation.auth_data.credential_data.aaguid != NULL_AAGUID
        ):
            return str(UUID(b2a_hex(cast(AttestedCredentialData, self.credential).aaguid).decode()))
        else:
            # FIXME: Add handling for UAF devices with AAID
            # Get the certificate FIDO U2F
            if "x5c" in self.attestation.att_stmt:
                cert = self.attestation.att_stmt["x5c"][0]
                certificate = load_der_x509_certificate(cert, default_backend())
            else:
                # ECDSAA attestation or self attestation?
                return None
            try:
                extension = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                subject_identifier = cast(SubjectKeyIdentifier, extension.value)
            except ExtensionNotFound:
                subject_identifier = SubjectKeyIdentifier.from_public_key(certificate.public_key())
            return b2a_hex(subject_identifier.digest).decode()

    def _get_metadata(self) -> AuthenticatorMetadata | None:
        """Get the appropriate metadata."""
        if self.identifier is None:
            return None
        try:
            return AuthenticatorMetadata.objects.get(identifier=self.identifier)
        except AuthenticatorMetadata.DoesNotExist:
            # Fallback - key identifiers can be stored as lists...
            pass
        try:
            return AuthenticatorMetadata.objects.get(identifier__contains=self.identifier)
        except AuthenticatorMetadata.DoesNotExist:
            return None

    def _prepare_store(self, root_certs: list[crypto.X509]) -> crypto.X509Store:
        """Prepare crypto store for verification."""
        store = crypto.X509Store()
        for root_cert in root_certs:
            store.add_cert(root_cert)
        if len(self.attestation.att_stmt["x5c"]) > 1:
            for interm_cert in self.attestation.att_stmt["x5c"][1:]:
                try:
                    store.add_cert(crypto.load_certificate(crypto.FILETYPE_ASN1, interm_cert))
                except crypto.Error:
                    # The certificate failed to load, ignore as if it is a missing link, the verification will fail
                    # It is possible that it is defined here as well as in metadata
                    pass
        return store

    @cached_property
    def metadata(self) -> AuthenticatorMetadata | None:
        """Verify and return the appropriate metada for this authenticator."""
        try:
            metadata = self._get_metadata()
        except MultipleObjectsReturned:
            metadata = None
        if metadata is None or "x5c" not in self.attestation.att_stmt:
            return metadata
        # Take the device certificate and try to validate against all certs in MDS
        device_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, self.attestation.att_stmt["x5c"][0])
        if metadata.detailed_metadata_entry != "":
            root_certs = json.loads(metadata.detailed_metadata_entry)["attestationRootCertificates"]
        else:
            root_certs = (
                json.loads(metadata.metadata_entry).get("metadataStatement", {}).get("attestationRootCertificates", [])
            )
            if not root_certs:
                return metadata
        conv_root_certs = [
            crypto.load_certificate(crypto.FILETYPE_PEM, PEM_CERT_TEMPLATE.format(root_cert).encode())
            for root_cert in root_certs
        ]
        if any(device_cert.to_cryptography() == c_r_cert.to_cryptography() for c_r_cert in conv_root_certs):
            # Certificate directly
            return metadata
        store = self._prepare_store(conv_root_certs)
        store_ctx = crypto.X509StoreContext(store, device_cert)
        try:
            store_ctx.verify_certificate()
        except crypto.X509StoreContextError:
            # The device certificate cannot be verified using the MDS certificate, do not trust the metadata
            return None
        return metadata


class AuthenticatorMetadata(models.Model):
    """Stores information from metadata service."""

    url = models.URLField(unique=True, null=True, blank=True)
    identifier = models.TextField(unique=True)
    metadata_entry = models.TextField()
    detailed_metadata_entry = models.TextField()

    @cached_property
    def level(self) -> AuthLevel:
        """Return last valid certification level."""
        decoded = json.loads(self.metadata_entry)
        status_dict = sorted(
            decoded["statusReports"], key=methodcaller("get", "effectiveDate", date.today().isoformat())
        )
        # The last status should be valid
        for status in status_dict[::-1]:
            # Is it directly a level?
            if status["status"] in tuple(AuthLevel):
                return AuthLevel(status["status"])
            elif status["status"] == "REVOKED":
                return AuthLevel.NONE
        return AuthLevel.NONE

    @cached_property
    def vulnerabilities(self) -> list[AuthVulnerability]:
        """Return a list of reported vulnerabilities."""
        decoded = json.loads(self.metadata_entry)
        vulnerabilities = tuple(AuthVulnerability)
        return [
            AuthVulnerability(s["status"]) for s in reversed(decoded["statusReports"]) if s["status"] in vulnerabilities
        ]

    @cached_property
    def is_update_available(self) -> bool:
        """Return whether an update is available."""
        decoded = json.loads(self.metadata_entry)
        return "UPDATE_AVAILABLE" in [status["status"] for status in decoded["statusReports"]]
