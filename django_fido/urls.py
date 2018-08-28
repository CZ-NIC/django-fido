"""URLs for django_fido application."""
from __future__ import unicode_literals

from django.conf.urls import url
from django.views.generic import TemplateView

from .views import (Fido2RegistrationRequestView, Fido2RegistrationView, U2fAuthenticationRequestView,
                    U2fAuthenticationView)

app_name = 'django_fido'
urlpatterns = [
    url('^registration/$', Fido2RegistrationView.as_view(), name='registration'),
    url('^registration/request/$', Fido2RegistrationRequestView.as_view(), name='registration_request'),
    url('^registration/done/$', TemplateView.as_view(template_name='django_fido/registration_done.html'),
        name='registration_done'),
    url('^authentication/$', U2fAuthenticationView.as_view(), name='authentication'),
    url('^authentication/u2f_request/$', U2fAuthenticationRequestView.as_view(), name='u2f_authentication_request'),
]
