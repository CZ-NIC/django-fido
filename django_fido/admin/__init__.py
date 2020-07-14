"""Django admin for django_fido models."""
from django.contrib import admin

from django_fido.models import Authenticator

from .authenticator import AuthenticatorAdmin

admin.site.register(Authenticator, AuthenticatorAdmin)
