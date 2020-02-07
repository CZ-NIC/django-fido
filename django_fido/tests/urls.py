"""URLs for django_fido application tests."""
from __future__ import unicode_literals

from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    url('', include('django_fido.urls')),
    url('admin/', admin.site.urls),
]
