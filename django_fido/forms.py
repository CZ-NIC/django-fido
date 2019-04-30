"""Forms for U2F registration and login."""
from __future__ import unicode_literals

import base64
import json

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject


class Fido2RegistrationForm(forms.Form):
    """Form for FIDO 2 registration responses."""

    client_data = forms.CharField(error_messages={'required': _("Operation wasn't completed.")},
                                  widget=forms.HiddenInput)
    attestation = forms.CharField(error_messages={'required': _("Operation wasn't completed.")},
                                  widget=forms.HiddenInput)

    class Media:
        """Add FIDO 2 related JS."""

        js = ('django_fido/js/fido2.js', )

    def clean_client_data(self) -> ClientData:
        """Return decoded client data."""
        value = self.cleaned_data['client_data']
        try:
            return ClientData(base64.b64decode(value))
        except ValueError:
            raise ValidationError(_('FIDO 2 response is malformed.'), code='invalid')

    def clean_attestation(self) -> AttestationObject:
        """Return decoded attestation object."""
        value = self.cleaned_data['attestation']
        try:
            return AttestationObject(base64.b64decode(value))
        except ValueError:
            raise ValidationError(_('FIDO 2 response is malformed.'), code='invalid')


class U2fResponseForm(forms.Form):
    """Form for U2F responses."""

    u2f_response = forms.CharField(error_messages={'required': _("Operation wasn't completed.")},
                                   widget=forms.HiddenInput)

    class Media:
        """Add U2F related JS."""

        js = ('django_fido/js/u2f-api.js', 'django_fido/js/u2f-registration.js')

    def clean_u2f_response(self):
        """Ensure U2F response is valid JSON."""
        u2f_response = self.cleaned_data['u2f_response']
        try:
            return json.loads(u2f_response)
        except ValueError:
            raise ValidationError(_('U2F response is malformed.'), code='invalid')
