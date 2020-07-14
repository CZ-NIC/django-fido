"""URLs for django_fido application."""
from django.conf.urls import url
from django.views.generic import TemplateView
from django.views.i18n import JavaScriptCatalog

from .views import (Fido2AuthenticationRequestView, Fido2AuthenticationView, Fido2RegistrationRequestView,
                    Fido2RegistrationView)

app_name = 'django_fido'
urlpatterns = [
    url('^registration/$', Fido2RegistrationView.as_view(), name='registration'),
    url('^registration/request/$', Fido2RegistrationRequestView.as_view(), name='registration_request'),
    url('^registration/done/$', TemplateView.as_view(template_name='django_fido/registration_done.html'),
        name='registration_done'),
    url('^authentication/$', Fido2AuthenticationView.as_view(), name='authentication'),
    url('^authentication/request/$', Fido2AuthenticationRequestView.as_view(), name='authentication_request'),
    url('^jsi18n/$', JavaScriptCatalog.as_view(), name='javascript_catalog'),
]
