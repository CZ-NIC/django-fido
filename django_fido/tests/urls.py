"""URLs for django_fido application tests."""
from __future__ import unicode_literals

from django.conf.urls import include, url

urlpatterns = [
    url('', include('django_fido.urls')),
]
