"""URLs for django_fido application."""
from __future__ import unicode_literals

from django.conf.urls import url
from django.views.generic import TemplateView

from .views import U2fAuthenticationRequestView, U2fAuthenticationView, U2fRegistrationRequestView, U2fRegistrationView

app_name = 'django_fido'
urlpatterns = [
    url('^registration/$', U2fRegistrationView.as_view(), name='registration'),
    url('^registration/u2f_request/$', U2fRegistrationRequestView.as_view(), name='u2f_registration_request'),
    url('^registration/done/$', TemplateView.as_view(template_name='django_fido/registration_done.html'),
        name='registration_done'),
    url('^authentication/$', U2fAuthenticationView.as_view(), name='authentication'),
    url('^authentication/u2f_request/$', U2fAuthenticationRequestView.as_view(), name='u2f_authentication_request'),
]
