"""Models for storing keys."""
from __future__ import unicode_literals

import base64

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.deconstruct import deconstructible
from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _

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


class U2fDevice(models.Model):
    """Represents a registered U2F device.

    U2F registered key fields:
     * version
     * key_handle
     * public_key
     * app_id
     * raw_transports - comma separated list of transports
     * attestation - Base64 encoded attestation certificate (X509 in DER format)

    Authentication fields:
     * counter
    """

    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='u2f_devices', on_delete=models.CASCADE)
    create_datetime = models.DateTimeField(auto_now_add=True)

    version = models.TextField()
    key_handle = models.TextField()
    public_key = models.TextField()
    app_id = models.TextField(blank=True, null=True, default=None)
    raw_transports = models.TextField(blank=True, null=True, default=None, validators=[TransportsValidator()])
    attestation = models.TextField(blank=True, null=True, default=None)

    counter = models.PositiveIntegerField(default=0)

    @property
    def transports(self):
        """Return U2F transports."""
        if not self.raw_transports:
            return []
        return self.raw_transports.split(',')

    @transports.setter
    def transports(self, value):
        if not value:
            self.raw_transports = None
        else:
            self.raw_transports = ','.join(value)

    @property
    def raw_attestation(self):
        """Return attestation certificate in DER format.

        @rtype: bytes
        """
        if self.attestation is None:
            return None
        return base64.b64decode(self.attestation)

    @raw_attestation.setter
    def raw_attestation(self, value):
        if value is None:
            self.attestation = None
        else:
            # Encode to base64 and the decode to six.text_type
            self.attestation = base64.b64encode(value).decode('utf-8')

    def get_registered_key(self):
        """Return data for `RegisteredKey` structure.

        See https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-javascript-api-v1.2-ps-20170411.html
        """
        return {
            'keyHandle': self.key_handle,
            'appId': self.app_id,
            'version': self.version,
            'transports': self.transports,
            # Avoid bug in python-u2flib-server - https://github.com/Yubico/python-u2flib-server/issues/45
            'publicKey': self.public_key,
        }
