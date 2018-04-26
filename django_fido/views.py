"""Views for U2F registration and login."""
from __future__ import unicode_literals

import logging
from abc import ABCMeta, abstractmethod
from copy import deepcopy

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.urls import reverse_lazy
from django.utils.encoding import force_text
from django.utils.six import with_metaclass
from django.utils.translation import ugettext_lazy as _
from django.views.generic import FormView, View
from six.moves import http_client
from six.moves.urllib.parse import urlsplit, urlunsplit
from u2flib_server import u2f

from .constants import REGISTRATION_REQUEST_SESSION_KEY, U2F_REGISTRATION_REQUEST
from .forms import U2fResponseForm
from .models import U2fDevice

_LOGGER = logging.getLogger(__name__)


class BaseU2fRequestView(with_metaclass(ABCMeta, View)):
    """Base view for U2F request views.

    @cvar session_key: Session key where the U2F request is stored.
    @cvar u2f_request_factory: Function which accepts `app_id` and `registered_keys` and returns U2F request.
    """

    session_key = None
    u2f_request_factory = None

    def get_app_id(self):
        """Return appId - base URL to the web."""
        # Correct `appId` for the web application doesn't have a path.
        # See https://developers.yubico.com/U2F/App_ID.html
        chunks = urlsplit(self.request.build_absolute_uri('/'))
        return urlunsplit((chunks.scheme, chunks.netloc, '', '', ''))

    @abstractmethod
    def get_user(self):
        """Return user which is subject of the request."""
        pass

    def create_u2f_request(self):
        """Create and return U2F request.

        @raise ValueError: If request can't be created.
        """
        user = self.get_user()
        assert user.is_authenticated, "User must not be anonymous for U2F requests."
        registered_keys = [key.get_registered_key() for key in user.u2f_devices.all()]
        try:
            return self.u2f_request_factory(self.get_app_id(), registered_keys)
        except ValueError as error:
            raise ValueError("Can't create U2F request: {}".format(error))

    def get(self, request):
        """Return JSON with U2F request."""
        try:
            u2f_request = self.create_u2f_request()
        except ValueError as error:
            return JsonResponse({'error': force_text(error)}, status=http_client.BAD_REQUEST)
        self.request.session[self.session_key] = u2f_request

        # Avoid bug in python-u2flib-server - https://github.com/Yubico/python-u2flib-server/issues/45
        # Remove `publicKey`s from the request.
        u2f_request_out = deepcopy(u2f_request)
        for key in u2f_request_out['registeredKeys']:
            key.pop('publicKey', None)

        return JsonResponse(u2f_request_out)


class U2fRegistrationRequestView(LoginRequiredMixin, BaseU2fRequestView):
    """Returns registration request and stores it in session."""

    session_key = REGISTRATION_REQUEST_SESSION_KEY
    u2f_request_factory = staticmethod(u2f.begin_registration)

    def get_user(self):
        """Return user which is subject of the request."""
        return self.request.user


class U2fRegistrationView(LoginRequiredMixin, FormView):
    """
    View to register U2F key.

    @cvar title: View title.
    @cvar u2f_request_url: URL at which an U2F request is provided.
    @cvar u2f_request_type: U2F request type
    """

    form_class = U2fResponseForm
    template_name = 'django_fido/u2f_form.html'
    success_url = reverse_lazy('django_fido:registration_done')

    title = _("Register U2F key")
    u2f_request_url = reverse_lazy('django_fido:u2f_registration_request')
    u2f_request_type = U2F_REGISTRATION_REQUEST

    def form_valid(self, form):
        """Complete the registration process."""
        u2f_request = self.request.session.pop(REGISTRATION_REQUEST_SESSION_KEY, None)
        if u2f_request is None:
            form.add_error(None, _('Registration request not found.'))
            return self.form_invalid(form)

        u2f_response = form.cleaned_data['u2f_response']

        try:
            device, attestation_cert = u2f.complete_registration(u2f_request, u2f_response)
        except (TypeError, ValueError, KeyError) as error:
            _LOGGER.info("U2F registration failed with error: %r", error)
            form.add_error(None, _('Registration failed.'))
            return self.form_invalid(form)

        U2fDevice.objects.create(
            user=self.request.user, version=device['version'], key_handle=device['keyHandle'],
            public_key=device['publicKey'], app_id=device['appId'], transports=device['transports'])
        return super(U2fRegistrationView, self).form_valid(form)