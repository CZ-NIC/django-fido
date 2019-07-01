"""Views for FIDO 2 registration and login."""
from __future__ import unicode_literals

import base64
import logging
from abc import ABCMeta, abstractmethod
from http.client import BAD_REQUEST
from typing import Dict, Optional, Tuple

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView
from django.core.exceptions import ValidationError
from django.forms import Form
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _
from django.views.generic import FormView, View
from fido2.ctap2 import AuthenticatorData
from fido2.server import ATTESTATION, Fido2Server, RelyingParty

from .constants import (AUTHENTICATION_USER_SESSION_KEY, FIDO2_AUTHENTICATION_REQUEST, FIDO2_REGISTRATION_REQUEST,
                        FIDO2_REQUEST_SESSION_KEY)
from .forms import Fido2AuthenticationForm, Fido2RegistrationForm
from .models import Authenticator

_LOGGER = logging.getLogger(__name__)


class Fido2ViewMixin(object):
    """
    Mixin with common methods for all FIDO 2 views.

    @cvar rp_name: Name of the relying party. If None, the RP ID is used instead.
    @cvar attestation: Attestation conveyance preference,
                       see https://www.w3.org/TR/webauthn/#enumdef-attestationconveyancepreference
    @cvar session_key: Session key where the FIDO 2 state is stored.
    """

    rp_name = None  # type: Optional[str]
    attestation = ATTESTATION.NONE
    session_key = FIDO2_REQUEST_SESSION_KEY

    def get_rp_id(self) -> str:
        """Return RP id - only a hostname for web services."""
        # `partition()` is faster than `split()`
        return self.request.get_host().partition(':')[0]  # type: ignore

    @property
    def server(self) -> Fido2Server:
        """Return FIDO 2 server instance."""
        rp = RelyingParty(self.get_rp_id(), self.rp_name)
        return Fido2Server(rp, attestation=self.attestation)

    @abstractmethod
    def get_user(self) -> AbstractBaseUser:
        """Return user which is subject of the request."""
        pass

    def get_credentials(self, user: AbstractBaseUser):
        """Return list of user's credentials."""
        return [a.credential for a in user.authenticators.all()]


class BaseFido2RequestView(Fido2ViewMixin, View, metaclass=ABCMeta):
    """Base view for FIDO 2 request views."""

    @abstractmethod
    def create_fido2_request(self) -> Tuple[Dict, Dict]:
        """Create and return FIDO 2 request.

        @raise ValueError: If request can't be created.
        """
        pass

    def get(self, request: HttpRequest) -> JsonResponse:
        """Return JSON with FIDO 2 request."""
        try:
            request_data, state = self.create_fido2_request()
        except ValueError as error:
            return JsonResponse({'error': force_text(error)}, status=BAD_REQUEST)

        # Encode challenge into base64 encoding
        challenge = request_data['publicKey']['challenge']
        challenge = base64.b64encode(challenge).decode('utf-8')
        request_data['publicKey']['challenge'] = challenge

        # Encode credential IDs, if exists - registration
        if 'excludeCredentials' in request_data['publicKey']:
            encoded_credentials = []
            for credential in request_data['publicKey']['excludeCredentials']:
                encoded_credential = credential.copy()
                encoded_credential['id'] = base64.b64encode(encoded_credential['id']).decode('utf-8')
                encoded_credentials.append(encoded_credential)
            request_data['publicKey']['excludeCredentials'] = encoded_credentials

        # Encode credential IDs, if exists - authentication
        if 'allowCredentials' in request_data['publicKey']:
            encoded_credentials = []
            for credential in request_data['publicKey']['allowCredentials']:
                encoded_credential = credential.copy()
                encoded_credential['id'] = base64.b64encode(encoded_credential['id']).decode('utf-8')
                encoded_credentials.append(encoded_credential)
            request_data['publicKey']['allowCredentials'] = encoded_credentials

        # Store the state into session
        self.request.session[self.session_key] = state

        return JsonResponse(request_data)


class Fido2RegistrationRequestView(LoginRequiredMixin, BaseFido2RequestView):
    """Returns registration request and stores its state in session."""

    def get_user(self):
        """Return user which is subject of the request."""
        return self.request.user

    def get_user_id(self, user: AbstractBaseUser) -> str:
        """Return a unique, persistent identifier of a user.

        Default implementation return user's username, but it is only secure if the username can't be reused.
        In such case, it is required to provide another identifier which would differentiate users.
        See https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-id and
        https://tools.ietf.org/html/rfc8266#section-6.1 for details.
        """
        return user.username

    def get_user_data(self, user: AbstractBaseUser) -> Dict[str, str]:
        """Convert user instance to user data for registration."""
        return {'id': self.get_user_id(user), 'name': user.username, 'displayName': user.get_full_name()}

    def create_fido2_request(self) -> Tuple[Dict, Dict]:
        """Create and return FIDO 2 registration request.

        @raise ValueError: If request can't be created.
        """
        user = self.get_user()
        assert user.is_authenticated, "User must not be anonymous for FIDO 2 requests."
        credentials = self.get_credentials(user)
        return self.server.register_begin(self.get_user_data(user), credentials)


class Fido2RegistrationView(LoginRequiredMixin, Fido2ViewMixin, FormView):
    """
    View to register FIDO 2 authenticator.

    @cvar title: View title.
    @cvar session_key: Session key where the FIDO 2 state is stored.
    @cvar fido2_request_url: URL at which an FIDO 2 request is provided.
    @cvar fido2_request_type: FIDO 2 request type
    """

    form_class = Fido2RegistrationForm
    template_name = 'django_fido/fido2_form.html'
    success_url = reverse_lazy('django_fido:registration_done')

    title = _("Register a new FIDO 2 authenticator")
    fido2_request_url = reverse_lazy('django_fido:registration_request')
    fido2_request_type = FIDO2_REGISTRATION_REQUEST

    def complete_registration(self, form: Form) -> AuthenticatorData:
        """
        Complete the registration.

        @raise ValidationError: If the registration can't be completed.
        """
        state = self.request.session.pop(self.session_key, None)
        if state is None:
            raise ValidationError(_('Registration request not found.'), code='missing')

        try:
            return self.server.register_complete(state, form.cleaned_data['client_data'],
                                                 form.cleaned_data['attestation'])
        except ValueError as error:
            _LOGGER.info("FIDO 2 registration failed with error: %r", error)
            raise ValidationError(_('Registration failed.'), code='invalid')

    def form_valid(self, form: Form) -> HttpResponse:
        """Complete the registration and return response."""
        try:
            # Return value is ignored, because we need whole attestation.
            self.complete_registration(form)
        except ValidationError as error:
            form.add_error(None, error)
            return self.form_invalid(form)

        Authenticator.objects.create(user=self.request.user, attestation=form.cleaned_data['attestation'])
        return super().form_valid(form)

    def form_invalid(self, form: Form) -> HttpResponse:
        """Clean the FIDO 2 request from session."""
        self.request.session.pop(self.session_key, None)
        return super().form_invalid(form)


class Fido2AuthenticationViewMixin(Fido2ViewMixin):
    """
    Mixin for FIDO 2 authentication views.

    Ensure user to be authenticated exists.
    """

    def get_user(self):
        """
        Return user which is to be authenticated.

        Return None, if no user could be found.
        """
        user_pk = self.request.session.get(AUTHENTICATION_USER_SESSION_KEY)
        if user_pk is None:
            return None
        return get_user_model().objects.get(pk=user_pk)

    def dispatch(self, request, *args, **kwargs):
        """Redirect to login, if user couldn't be found."""
        user = self.get_user()
        if user is None or not user.is_authenticated:
            return redirect(settings.LOGIN_URL)
        return super().dispatch(request, *args, **kwargs)  # type: ignore


class Fido2AuthenticationRequestView(Fido2AuthenticationViewMixin, BaseFido2RequestView):
    """Returns authentication request and stores its state in session."""

    def create_fido2_request(self) -> Tuple[Dict, Dict]:
        """Create and return FIDO 2 authentication request.

        @raise ValueError: If request can't be created.
        """
        user = self.get_user()
        assert user.is_authenticated, "User must not be anonymous for FIDO 2 requests."
        credentials = self.get_credentials(user)
        if not credentials:
            raise ValueError("Can't create FIDO 2 authentication request, no authenticators.")

        return self.server.authenticate_begin(credentials)


class Fido2AuthenticationView(Fido2AuthenticationViewMixin, LoginView):
    """
    View to authenticate FIDO 2 key.

    @cvar title: View title.
    @cvar fido2_request_url: URL at which an FIDO 2 request is provided.
    @cvar fido2_request_type: FIDO 2 request type
    """

    form_class = Fido2AuthenticationForm
    template_name = 'django_fido/fido2_form.html'

    title = _("Authenticate a FIDO 2 authenticator")
    fido2_request_url = reverse_lazy('django_fido:authentication_request')
    fido2_request_type = FIDO2_AUTHENTICATION_REQUEST

    def get_form_kwargs(self):
        """Return form arguments - exclude request."""
        kwargs = super().get_form_kwargs()
        # Fido2AuthenticationForm doesn't accept request.
        kwargs.pop('request', None)
        return kwargs

    def complete_authentication(self, form: Form) -> AbstractBaseUser:
        """
        Complete the authentication.

        @raise ValidationError: If the authentication can't be completed.
        """
        state = self.request.session.pop(self.session_key, None)
        if state is None:
            raise ValidationError(_('Authentication request not found.'), code='missing')

        user = authenticate(request=self.request, user=self.get_user(), fido2_server=self.server, fido2_state=state,
                            fido2_response=form.cleaned_data)
        if user is None:
            raise ValidationError(_('Authentication failed.'), code='invalid')
        return user

    def form_valid(self, form: Form) -> HttpResponse:
        """Complete the authentication and return response."""
        try:
            user = self.complete_authentication(form)
        except ValidationError as error:
            form.add_error(None, error)
            return self.form_invalid(form)

        login(self.request, user)
        # Ensure user is deleted from session.
        self.request.session.pop(AUTHENTICATION_USER_SESSION_KEY, None)

        return redirect(self.get_success_url())

    def form_invalid(self, form: Form) -> HttpResponse:
        """Clean the FIDO 2 request from session."""
        self.request.session.pop(self.session_key, None)
        return super().form_invalid(form)
