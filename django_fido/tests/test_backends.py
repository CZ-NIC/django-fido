"""Test `django_fido.backends` module."""
import base64

from django.contrib.auth import get_user_model
from django.contrib.messages.storage.cookie import CookieStorage
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from fido2.client import ClientData
from fido2.ctap2 import AuthenticatorData
from fido2.server import Fido2Server
from mock import sentinel

from django_fido.backends import Fido2AuthenticationBackend, Fido2GeneralAuthenticationBackend, is_fido_backend_used
from django_fido.models import Authenticator

from .data import (ATTESTATION_OBJECT, AUTHENTICATION_CHALLENGE, AUTHENTICATION_CLIENT_DATA, AUTHENTICATOR_DATA,
                   CREDENTIAL_ID, HOSTNAME, PASSWORD, SIGNATURE, USERNAME)

try:
    from fido2.webauthn import PublicKeyCredentialRpEntity, UserVerificationRequirement
except ImportError:
    from fido2.server import (USER_VERIFICATION as UserVerificationRequirement,
                              RelyingParty as PublicKeyCredentialRpEntity)

User = get_user_model()


class TestFido2AuthenticationBackend(TestCase):
    """Test `Fido2AuthenticationBackend` class."""

    backend = Fido2AuthenticationBackend()

    server = Fido2Server(PublicKeyCredentialRpEntity(HOSTNAME, HOSTNAME))

    state = {'challenge': AUTHENTICATION_CHALLENGE, 'user_verification': UserVerificationRequirement.PREFERRED}
    fido2_response = {'client_data': ClientData(base64.b64decode(AUTHENTICATION_CLIENT_DATA)),
                      'credential_id': base64.b64decode(CREDENTIAL_ID),
                      'authenticator_data': AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
                      'signature': base64.b64decode(SIGNATURE)}

    def setUp(self):
        self.user = User.objects.create_user(USERNAME)
        self.device = Authenticator.objects.create(user=self.user,
                                                   credential_id_data=CREDENTIAL_ID,
                                                   attestation_data=ATTESTATION_OBJECT)

    def test_authenticate(self):
        authenticated_user = self.backend.authenticate(sentinel.request, self.user, self.server, self.state,
                                                       self.fido2_response)

        self.assertEqual(authenticated_user, self.user)
        self.assertQuerysetEqual(Authenticator.objects.values_list('user', 'counter'), [(self.user.pk, 152)],
                                 transform=tuple)

    def test_authenticate_wrong_counter(self):
        self.device.counter = 160
        self.device.save()
        request = RequestFactory().get('/dummy/')
        request._messages = CookieStorage(request)

        self.assertRaisesMessage(PermissionDenied, "Counter didn't increase.",
                                 self.backend.authenticate, request, self.user, self.server, self.state,
                                 self.fido2_response)

        self.assertQuerysetEqual(Authenticator.objects.values_list('user', 'counter'), [(self.user.pk, 160)],
                                 transform=tuple)

    def test_authenticate_invalid_response(self):
        fido2_response = {'client_data': ClientData(base64.b64decode(AUTHENTICATION_CLIENT_DATA)),
                          'credential_id': base64.b64decode(CREDENTIAL_ID),
                          'authenticator_data': AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
                          'signature': b'INVALID'}
        self.assertIsNone(
            self.backend.authenticate(sentinel.request, self.user, self.server, self.state, fido2_response))

    def test_mark_device_used(self):
        self.backend.mark_device_used(self.device, 42)

        self.assertQuerysetEqual(Authenticator.objects.values_list('user', 'counter'), [(self.user.pk, 42)],
                                 transform=tuple)

    def test_mark_device_used_equal(self):
        # Test device returned the same counter.
        self.device.counter = 42
        self.device.save()

        self.assertRaisesMessage(ValueError, "Counter didn't increase.", self.backend.mark_device_used, self.device, 42)

        self.assertQuerysetEqual(Authenticator.objects.values_list('user', 'counter'), [(self.user.pk, 42)],
                                 transform=tuple)

    def test_mark_device_used_decrease(self):
        # Test device returned lower counter.
        self.device.counter = 42
        self.device.save()

        self.assertRaisesMessage(ValueError, "Counter didn't increase.", self.backend.mark_device_used, self.device, 41)

        self.assertQuerysetEqual(Authenticator.objects.values_list('user', 'counter'), [(self.user.pk, 42)],
                                 transform=tuple)

    def test_get_user(self):
        self.assertEqual(self.backend.get_user(self.user.pk), self.user)

    def test_get_user_unknown(self):
        self.assertIsNone(self.backend.get_user(42))


@override_settings(DJANGO_FIDO_AUTHENTICATION_BACKENDS=['django.contrib.auth.backends.ModelBackend'])
class TestFido2GeneralAuthenticationBackend(TestCase):
    """Test `Fido2GeneralAuthenticationBackend` class."""

    backend = Fido2GeneralAuthenticationBackend()

    server = Fido2Server(PublicKeyCredentialRpEntity(HOSTNAME, HOSTNAME))

    state = {'challenge': AUTHENTICATION_CHALLENGE, 'user_verification': UserVerificationRequirement.PREFERRED}
    fido2_response = {'client_data': ClientData(base64.b64decode(AUTHENTICATION_CLIENT_DATA)),
                      'credential_id': base64.b64decode(CREDENTIAL_ID),
                      'authenticator_data': AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
                      'signature': base64.b64decode(SIGNATURE)}

    def setUp(self):
        self.user = User.objects.create_user(USERNAME, password=PASSWORD)
        self.device = Authenticator.objects.create(user=self.user,
                                                   credential_id_data=CREDENTIAL_ID,
                                                   attestation_data=ATTESTATION_OBJECT)

    def test_authenticate(self):
        authenticated_user = self.backend.authenticate(
            sentinel.request, USERNAME, PASSWORD, self.server, self.state, self.fido2_response)
        self.assertEqual(authenticated_user, self.user)
        self.assertQuerysetEqual(Authenticator.objects.values_list('user', 'counter'), [(self.user.pk, 152)],
                                 transform=tuple)

    def test_authenticate_wrong_password(self):
        authenticated_user = self.backend.authenticate(
            sentinel.request, USERNAME, 'wrong_password', self.server, self.state, self.fido2_response)
        self.assertEqual(authenticated_user, None)
        self.assertQuerysetEqual(Authenticator.objects.values_list('user', 'counter'), [(self.user.pk, 0)],
                                 transform=tuple)


class TestIsFidoBackendUsed(SimpleTestCase):

    @override_settings(AUTHENTICATION_BACKENDS=['django_fido.backends.Fido2AuthenticationBackend'])
    def test_is_used(self):
        self.assertTrue(is_fido_backend_used())

    @override_settings(AUTHENTICATION_BACKENDS=['django.contrib.auth.backends.ModelBackend'])
    def test_is_not_used(self):
        self.assertFalse(is_fido_backend_used())
