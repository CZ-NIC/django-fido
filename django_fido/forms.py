"""Forms for FIDO 2 registration and login."""
from __future__ import unicode_literals

import base64

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData


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


class Fido2AuthenticationForm(forms.Form):
    """Form for FIDO 2 authentication responses."""

    client_data = forms.CharField(error_messages={'required': _("Operation wasn't completed.")},
                                  widget=forms.HiddenInput)
    credential_id = forms.CharField(error_messages={'required': _("Operation wasn't completed.")},
                                    widget=forms.HiddenInput)
    authenticator_data = forms.CharField(error_messages={'required': _("Operation wasn't completed.")},
                                         widget=forms.HiddenInput)
    signature = forms.CharField(error_messages={'required': _("Operation wasn't completed.")},
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

    def clean_credential_id(self) -> bytes:
        """Return decoded credential ID."""
        value = self.cleaned_data['credential_id']
        try:
            return base64.b64decode(value)
        except ValueError:
            raise ValidationError(_('FIDO 2 response is malformed.'), code='invalid')

    def clean_authenticator_data(self) -> AuthenticatorData:
        """Return decoded authenticator data."""
        value = self.cleaned_data['authenticator_data']
        try:
            return AuthenticatorData(base64.b64decode(value))
        except ValueError:
            raise ValidationError(_('FIDO 2 response is malformed.'), code='invalid')

    def clean_signature(self) -> bytes:
        """Return decoded signature."""
        value = self.cleaned_data['signature']
        try:
            return base64.b64decode(value)
        except ValueError:
            raise ValidationError(_('FIDO 2 response is malformed.'), code='invalid')
