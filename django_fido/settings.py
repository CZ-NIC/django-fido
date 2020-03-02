"""Django settings specific for django_fido."""
from __future__ import unicode_literals

from appsettings import AppSettings, BooleanSetting, CallablePathSetting, NestedListSetting, StringSetting
from django.contrib.auth.backends import ModelBackend


class DjangoFidoSettings(AppSettings):
    """Application specific settings."""

    authentication_backends = NestedListSetting(
        inner_setting=CallablePathSetting(),
        default=(ModelBackend,),
    )
    rp_name = StringSetting(default=None)
    two_step_auth = BooleanSetting(default=True)

    class Meta:
        """Meta class."""

        setting_prefix = 'django_fido_'


SETTINGS = DjangoFidoSettings()
