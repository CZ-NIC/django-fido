"""Django settings specific for django_fido."""
from __future__ import unicode_literals

from appsettings import AppSettings, StringSetting


class DjangoFidoSettings(AppSettings):
    """Application specific settings."""

    rp_name = StringSetting(default=None)

    class Meta:
        """Meta class."""

        setting_prefix = 'django_fido_'


SETTINGS = DjangoFidoSettings()
