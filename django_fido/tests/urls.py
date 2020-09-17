"""URLs for django_fido application tests."""
from django.conf.urls import include, url
from django.contrib import admin

from django_fido.views import AttestationConveyancePreference, Fido2RegistrationView

urlpatterns = [
    url('', include('django_fido.urls')),
    url('admin/', admin.site.urls),
    url('direct_registration/',
        Fido2RegistrationView.as_view(attestation=AttestationConveyancePreference.DIRECT),
        name='registration_direct'),
]
