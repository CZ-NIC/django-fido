"""django_fido app config."""
from __future__ import unicode_literals

from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

from django_fido.settings import DjangoFidoSettings


class DjangoFidoConfig(AppConfig):
    """django_fido app config."""

    name = 'django_fido'
    verbose_name = _('Django application for FIDO protocol')

    def ready(self):
        """Check configuration."""
        DjangoFidoSettings.check()
