"""Authentication backends for Django FIDO."""

from __future__ import annotations

import base64
import logging
from abc import ABC, abstractmethod
from typing import Any

from django.contrib import messages
from django.contrib.auth import get_backends, get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.base_user import AbstractBaseUser
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _
from fido2.server import Fido2Server

from .models import Authenticator
from .settings import SETTINGS

_LOGGER = logging.getLogger(__name__)


def is_fido_backend_used() -> bool:
    """Detect whether FIDO2 authentication backend is used."""
    for auth_backend in get_backends():
        if isinstance(auth_backend, (Fido2AuthenticationBackend, Fido2GeneralAuthenticationBackend)):
            return True

    return False


class BaseFido2AuthenticationBackend(ABC):
    """Base class for authenticating user using FIDO 2.

    @cvar counter_error_message: Error message in case FIDO 2 device counter didn't increase.
    """

    counter_error_message = _("Counter of the FIDO 2 device decreased. Device may have been duplicated.")

    @abstractmethod
    def authenticate(
        self,
        request: HttpRequest,
        user: AbstractBaseUser,
        fido2_server: Fido2Server,
        fido2_state: dict[str, str],
        fido2_response: dict[str, Any],
    ) -> AbstractBaseUser | None:
        """Authenticate to be implemented."""
        raise NotImplementedError

    def mark_device_used(self, device, counter):
        """Update FIDO 2 device usage information."""
        if counter == 0 and device.counter == 0:
            # Counter is unsupported by the device, bail out early
            return
        if counter <= device.counter:
            _LOGGER.info("FIDO 2 authentication failed because of not increasing counter.")
            raise ValueError("Counter didn't increase.")
        device.counter = counter
        device.full_clean()
        device.save()

    def get_user(self, user_id):
        """Return user based on its ID."""
        try:
            return get_user_model().objects.get(pk=user_id)
        except get_user_model().DoesNotExist:
            return None


class Fido2AuthenticationBackend(BaseFido2AuthenticationBackend):
    """Authenticate user using FIDO 2."""

    def authenticate(
        self,
        request: HttpRequest,
        user: AbstractBaseUser,
        fido2_server: Fido2Server,
        fido2_state: dict[str, str],
        fido2_response: dict[str, Any],
    ) -> AbstractBaseUser | None:
        """Authenticate using FIDO 2."""
        credentials = [a.credential for a in user.authenticators.all()]
        try:
            credential = fido2_server.authenticate_complete(
                fido2_state,
                credentials,
                fido2_response["credential_id"],
                fido2_response["client_data"],
                fido2_response["authenticator_data"],
                fido2_response["signature"],
            )
        except ValueError as error:
            _LOGGER.info("FIDO 2 authentication failed with error: %r", error)
            return None

        device = user.authenticators.get(credential_id_data=base64.b64encode(credential.credential_id).decode("utf-8"))
        try:
            self.mark_device_used(device, fido2_response["authenticator_data"].counter)
        except ValueError:
            # Raise `PermissionDenied` to stop the authentication process and skip remaining backends.
            messages.error(request, self.counter_error_message)
            raise PermissionDenied("Counter didn't increase.") from None
        return user


class Fido2PasswordlessAuthenticationBackend(BaseFido2AuthenticationBackend):
    """Authenticate user using FIDO 2 passwordlessly using supplied user handle."""

    def authenticate(
        self,
        request: HttpRequest,
        user: AbstractBaseUser | None,
        fido2_server: Fido2Server,
        fido2_state: dict[str, str],
        fido2_response: dict[str, Any],
    ) -> AbstractBaseUser | None:
        """Authenticate using FIDO 2."""
        user_handle = fido2_response["user_handle"]

        try:
            device = Authenticator.objects.get(user_handle=user_handle)
            user = device.user
            credentials = [device.credential]
            fido2_server.authenticate_complete(
                fido2_state,
                credentials,
                fido2_response["credential_id"],
                fido2_response["client_data"],
                fido2_response["authenticator_data"],
                fido2_response["signature"],
            )
        except ValueError as error:
            _LOGGER.info("FIDO 2 authentication failed with error: %r", error)
            return None
        except Authenticator.DoesNotExist:
            _LOGGER.info("FIDO 2 authentication could not find user handle: %s", user_handle)
            return None

        try:
            self.mark_device_used(device, fido2_response["authenticator_data"].counter)
        except ValueError:
            # Raise `PermissionDenied` to stop the authentication process and skip remaining backends.
            messages.error(request, self.counter_error_message)
            raise PermissionDenied("Counter didn't increase.") from None
        return user


class Fido2GeneralAuthenticationBackend(ModelBackend):
    """Authenticated user using any username-password backend and Fido2AuthenticationBackend."""

    def __init__(self, *args, **kwargs):
        """Initialize backend."""
        super().__init__(*args, **kwargs)
        self.fido_backend = Fido2AuthenticationBackend()

    def authenticate(
        self,
        request: HttpRequest,
        username: str,
        password: str,
        fido2_server: Fido2Server,
        fido2_state: dict[str, str],
        fido2_response: dict[str, Any],
        **kwargs,
    ) -> AbstractBaseUser | None:
        """Authenticate using username, password and FIDO 2 token."""
        for auth_backend in SETTINGS.authentication_backends:
            user = auth_backend().authenticate(request, username=username, password=password, **kwargs)
            if user is not None:
                return self.fido_backend.authenticate(request, user, fido2_server, fido2_state, fido2_response)

        return None
