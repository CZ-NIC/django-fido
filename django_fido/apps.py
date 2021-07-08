"""django_fido app config."""
from django.apps import AppConfig
from django.test.signals import setting_changed
from django.utils.translation import gettext_lazy as _

from django_fido.settings import SETTINGS


class DjangoFidoConfig(AppConfig):
    """django_fido app config."""

    name = 'django_fido'
    verbose_name = _('Django application for FIDO protocol')

    def ready(self):
        """Check configuration."""
        SETTINGS.check()
        setting_changed.connect(SETTINGS.invalidate_cache)
