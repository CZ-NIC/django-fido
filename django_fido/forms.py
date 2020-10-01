"""Forms for FIDO 2 registration and login."""
import base64

from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.server import Fido2Server


class Fido2RegistrationForm(forms.Form):
    """Form for FIDO 2 registration responses."""

    client_data = forms.CharField(error_messages={'required': _("Operation wasn't completed.")},
                                  widget=forms.HiddenInput)
    attestation = forms.CharField(error_messages={'required': _("Operation wasn't completed.")},
                                  widget=forms.HiddenInput)
    label = forms.CharField(required=False, max_length=255, label=_("Label"))

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


class Fido2ModelAuthenticationForm(AuthenticationForm, Fido2AuthenticationForm):
    """Authentication form with username, password and FIDO 2 credentials."""

    def __init__(self, request: HttpRequest, fido2_server: Fido2Server, session_key: str, *args, **kwargs):
        """Initialize form."""
        super().__init__(request, *args, **kwargs)
        self.fido2_server = fido2_server
        self.session_key = session_key
        self.error_messages['invalid_login'] = _(
            "Please enter a correct %(username)s and password and use valid FIDO2 security key."
        )

    def clean(self):
        """Authenticate user."""
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        state = self.request.session.pop(self.session_key, None)
        if state is None:
            raise ValidationError(_('Authentication request not found.'), code='missing')

        self.user_cache = authenticate(
            self.request,
            username=username,
            password=password,
            fido2_server=self.fido2_server,
            fido2_state=state,
            fido2_response=self.cleaned_data,
        )
        if self.user_cache is None:
            raise self.get_invalid_login_error()
        else:
            self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data

    def get_invalid_login_error(self):
        """Get invalid login error."""
        # FIXME: This method of AuthenticationForm was first introduced in Django 2.1.
        # As soon as we stop supporting lower Django versions, we can delete it.
        return forms.ValidationError(
            self.error_messages['invalid_login'],
            code='invalid_login',
            params={'username': self.username_field.verbose_name},
        )
