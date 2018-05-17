"""Forms for U2F registration and login."""
from __future__ import unicode_literals

import json

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _


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
