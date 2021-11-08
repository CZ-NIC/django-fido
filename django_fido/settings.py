"""Django settings specific for django_fido."""
from typing import List, Optional, cast

from appsettings import (AppSettings, BooleanSetting, CallablePathSetting, FileSetting, NestedDictSetting,
                         NestedListSetting, PositiveIntegerSetting, Setting, StringSetting)
from django.core.exceptions import ImproperlyConfigured, ValidationError


def timeout_validator(value):
    """Validate timeouts - must contain a number or tuple with two numbers."""
    if isinstance(value, (float, int)):
        return
    if isinstance(value, tuple) and len(value) == 2 and all(isinstance(v, (float, int)) for v in value):
        return
    raise ValidationError('Value %(value)s must be a float, int or a tuple with 2 float or int items.',
                          params={'value': value})


class DjangoFidoSettings(AppSettings):
    """Application specific settings."""

    authentication_backends = cast(List, NestedListSetting(
        inner_setting=CallablePathSetting(),
        default=('django.contrib.auth.backends.ModelBackend',),
        transform_default=True,
    ))
    rp_name = cast(Optional[str], StringSetting(default=None))
    two_step_auth = BooleanSetting(default=True)
    metadata_service = NestedDictSetting(settings=dict(
        access_token=StringSetting(default=None),
        mds_format=PositiveIntegerSetting(default=2),
        url=StringSetting(default='https://mds2.fidoalliance.org/'),
        timeout=Setting(default=3, validators=[timeout_validator]),
        disable_cert_verification=BooleanSetting(default=False),
        certificate=NestedListSetting(inner_setting=FileSetting(), default=[]),
        crl_list=NestedListSetting(inner_setting=FileSetting(), default=[]),
    ), default=None)
    resident_key = BooleanSetting(default=False)
    passwordless_auth = BooleanSetting(default=False)

    @classmethod
    def check(cls):
        """Extend parent class check method to perform further project specific settings check."""
        super(DjangoFidoSettings, cls).check()

        # check passwordless settings
        if cls.settings['passwordless_auth'].get_value() and not cls.settings['resident_key'].get_value():
            raise ImproperlyConfigured("To use passwordless auth, RESIDENT_KEY settings must be set to True")

        if cls.settings['passwordless_auth'].get_value() and cls.settings['two_step_auth'].get_value():
            raise ImproperlyConfigured("To use passwordless auth, TWO_STEP_AUTH must be set to False")

    class Meta:
        """Meta class."""

        setting_prefix = 'django_fido_'


SETTINGS = DjangoFidoSettings()
