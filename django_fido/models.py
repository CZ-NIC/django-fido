"""Models for storing keys."""
from __future__ import unicode_literals

import base64
import warnings

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.deconstruct import deconstructible
from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _
from fido2.ctap2 import AttestationObject, AttestedCredentialData

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
    counter = models.PositiveIntegerField(default=0)

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
