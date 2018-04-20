"""Authentication backends for Django FIDO."""
from __future__ import unicode_literals

import logging

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.utils.translation import ugettext_lazy as _
from u2flib_server import u2f

_LOGGER = logging.getLogger(__name__)


class U2fAuthenticationBackend(object):
    """
    Authenticate user using U2F.

    @cvar counter_error_message: Error message in case U2F device counter didn't increase.
    """

    counter_error_message = _("Counter of the U2F device decreased. Device may have been duplicated.")

    def authenticate(self, request, user, u2f_request, u2f_response):
        """Authenticate using U2F."""
        try:
            device, counter, user_presence = u2f.complete_authentication(u2f_request, u2f_response)
        except (TypeError, ValueError, KeyError) as error:
            _LOGGER.info("U2F authentication failed with error: %r", error)
            return None

        u2f_device = user.u2f_devices.get(key_handle=device['keyHandle'])
        try:
            self.mark_device_used(u2f_device, counter)
        except ValueError:
            # Raise `PermissionDenied` to stop the authentication process and skip remaining backends.
            messages.error(request, self.counter_error_message)
            raise PermissionDenied("Counter didn't increase.")
        return user

    def mark_device_used(self, u2f_device, counter):
        """Update U2F device usage information."""
        if counter <= u2f_device.counter:
            _LOGGER.info("U2F authentication failed because of not increasing counter.")
            raise ValueError("Counter didn't increase.")
        u2f_device.counter = counter
        u2f_device.full_clean()
        u2f_device.save()

    def get_user(self, user_id):
        """Return user based on its ID."""
        try:
            return get_user_model().objects.get(pk=user_id)
        except get_user_model().DoesNotExist:
            return None
