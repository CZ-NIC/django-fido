"""URLs for django_fido application."""
from django.urls import re_path
from django.views.generic import TemplateView
from django.views.i18n import JavaScriptCatalog

from .views import (Fido2AuthenticationRequestView, Fido2AuthenticationView, Fido2RegistrationRequestView,
                    Fido2RegistrationView)

app_name = 'django_fido'
urlpatterns = [
    re_path('^registration/$', Fido2RegistrationView.as_view(), name='registration'),
    re_path('^registration/request/$', Fido2RegistrationRequestView.as_view(), name='registration_request'),
    re_path('^registration/done/$', TemplateView.as_view(template_name='django_fido/registration_done.html'),
            name='registration_done'),
    re_path('^authentication/$', Fido2AuthenticationView.as_view(), name='authentication'),
    re_path('^authentication/request/$', Fido2AuthenticationRequestView.as_view(), name='authentication_request'),
    re_path('^jsi18n/$', JavaScriptCatalog.as_view(), name='javascript_catalog'),
]
