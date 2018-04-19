"""URLs for django_fido application."""
from __future__ import unicode_literals

from django.conf.urls import url

from .views import U2fRegistrationRequestView

app_name = 'django_fido'
urlpatterns = [
    url('^registration/u2f_request/$', U2fRegistrationRequestView.as_view(), name='u2f_registration_request'),
]
