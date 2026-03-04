"""Test `django_fido.backends` module."""

import base64
from unittest import skipIf
from unittest.mock import sentinel

import django
from django.contrib.auth import get_user_model
from django.contrib.messages.storage.cookie import CookieStorage
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from fido2.server import Fido2Server
from fido2.webauthn import (
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    UserVerificationRequirement,
)

from django_fido.backends import (
    Fido2AuthenticationBackend,
    Fido2GeneralAuthenticationBackend,
    Fido2PasswordlessAuthenticationBackend,
    is_fido_backend_used,
)
from django_fido.models import Authenticator

from .data import (
    ATTESTATION_OBJECT,
    AUTHENTICATION_CHALLENGE,
    AUTHENTICATION_CLIENT_DATA,
    AUTHENTICATOR_DATA,
    CREDENTIAL_ID,
    HOSTNAME,
    PASSWORD,
    SIGNATURE,
    USER_HANDLE,
    USER_HANDLE_B64,
    USERNAME,
)

User = get_user_model()


class TestFido2AuthenticationBackend(TestCase):
    """Test `Fido2AuthenticationBackend` class."""

    backend = Fido2AuthenticationBackend()

    server = Fido2Server(PublicKeyCredentialRpEntity(HOSTNAME, HOSTNAME))

    state = {"challenge": AUTHENTICATION_CHALLENGE, "user_verification": UserVerificationRequirement.PREFERRED}
    fido2_response = {
        "client_data": CollectedClientData(base64.b64decode(AUTHENTICATION_CLIENT_DATA)),
        "credential_id": base64.b64decode(CREDENTIAL_ID),
        "authenticator_data": AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
        "signature": base64.b64decode(SIGNATURE),
    }

    def setUp(self):
        self.user = User.objects.create_user(USERNAME)
        self.device = Authenticator.objects.create(
            user=self.user, credential_id_data=CREDENTIAL_ID, attestation_data=ATTESTATION_OBJECT
        )

    def test_authenticate(self):
        authenticated_user = self.backend.authenticate(
            sentinel.request, self.user, self.server, self.state, self.fido2_response
        )

        self.assertEqual(authenticated_user, self.user)
        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 152)], transform=tuple
        )

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_aauthenticate(self):
        authenticated_user = await self.backend.aauthenticate(
            sentinel.request, self.user, self.server, self.state, self.fido2_response
        )

        self.assertEqual(authenticated_user, self.user)
        self.assertQuerySetEqual(
            [a async for a in Authenticator.objects.values_list("user", "counter")],
            [(self.user.pk, 152)],
            transform=tuple,
        )

    def test_authenticate_wrong_counter(self):
        self.device.counter = 160
        self.device.save()
        request = RequestFactory().get("/dummy/")
        request._messages = CookieStorage(request)

        self.assertRaisesMessage(
            PermissionDenied,
            "Counter didn't increase.",
            self.backend.authenticate,
            request,
            self.user,
            self.server,
            self.state,
            self.fido2_response,
        )

        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 160)], transform=tuple
        )

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_aauthenticate_wrong_counter(self):
        self.device.counter = 160
        await self.device.asave()
        request = RequestFactory().get("/dummy/")
        request._messages = CookieStorage(request)

        with self.assertRaisesMessage(PermissionDenied, "Counter didn't increase."):
            await self.backend.aauthenticate(request, self.user, self.server, self.state, self.fido2_response)

        self.assertQuerySetEqual(
            [a async for a in Authenticator.objects.values_list("user", "counter")],
            [(self.user.pk, 160)],
            transform=tuple,
        )

    def test_authenticate_invalid_response(self):
        fido2_response = {
            "client_data": CollectedClientData(base64.b64decode(AUTHENTICATION_CLIENT_DATA)),
            "credential_id": base64.b64decode(CREDENTIAL_ID),
            "authenticator_data": AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
            "signature": b"INVALID",
        }
        self.assertIsNone(
            self.backend.authenticate(sentinel.request, self.user, self.server, self.state, fido2_response)
        )

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_aauthenticate_invalid_response(self):
        fido2_response = {
            "client_data": CollectedClientData(base64.b64decode(AUTHENTICATION_CLIENT_DATA)),
            "credential_id": base64.b64decode(CREDENTIAL_ID),
            "authenticator_data": AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
            "signature": b"INVALID",
        }
        self.assertIsNone(
            await self.backend.aauthenticate(sentinel.request, self.user, self.server, self.state, fido2_response)
        )

    def test_mark_device_used(self):
        self.backend.mark_device_used(self.device, 42)

        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 42)], transform=tuple
        )

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_amark_device_used(self):
        await self.backend.amark_device_used(self.device, 42)

        self.assertQuerySetEqual(
            [a async for a in Authenticator.objects.values_list("user", "counter")],
            [(self.user.pk, 42)],
            transform=tuple,
        )

    def test_mark_device_used_equal(self):
        # Test device returned the same counter.
        self.device.counter = 42
        self.device.save()

        self.assertRaisesMessage(ValueError, "Counter didn't increase.", self.backend.mark_device_used, self.device, 42)

        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 42)], transform=tuple
        )

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_amark_device_used_equal(self):
        # Test device returned the same counter.
        self.device.counter = 42
        await self.device.asave()

        with self.assertRaisesMessage(ValueError, "Counter didn't increase."):
            await self.backend.amark_device_used(self.device, 42)

        self.assertQuerySetEqual(
            [a async for a in Authenticator.objects.values_list("user", "counter")],
            [(self.user.pk, 42)],
            transform=tuple,
        )

    def test_mark_device_used_unsupported(self):
        # Test device is allowed if counter is unsupported
        self.device.counter = 0
        self.device.save()

        self.backend.mark_device_used(self.device, 0)

        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 0)], transform=tuple
        )

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_amark_device_used_unsupported(self):
        # Test device is allowed if counter is unsupported
        self.device.counter = 0
        await self.device.asave()

        await self.backend.amark_device_used(self.device, 0)

        self.assertQuerySetEqual(
            [a async for a in Authenticator.objects.values_list("user", "counter")],
            [(self.user.pk, 0)],
            transform=tuple,
        )

    def test_mark_device_used_decrease(self):
        # Test device returned lower counter.
        self.device.counter = 42
        self.device.save()

        self.assertRaisesMessage(ValueError, "Counter didn't increase.", self.backend.mark_device_used, self.device, 41)

        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 42)], transform=tuple
        )

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_amark_device_used_decrease(self):
        # Test device returned lower counter.
        self.device.counter = 42
        await self.device.asave()

        with self.assertRaisesMessage(ValueError, "Counter didn't increase."):
            await self.backend.amark_device_used(self.device, 41)

        self.assertQuerySetEqual(
            [a async for a in Authenticator.objects.values_list("user", "counter")],
            [(self.user.pk, 42)],
            transform=tuple,
        )

    def test_get_user(self):
        self.assertEqual(self.backend.get_user(self.user.pk), self.user)

    def test_get_user_unknown(self):
        self.assertIsNone(self.backend.get_user(42))

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_aget_user(self):
        self.assertEqual(await self.backend.aget_user(self.user.pk), self.user)

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_aget_user_unknown(self):
        self.assertIsNone(await self.backend.aget_user(42))


@override_settings(DJANGO_FIDO_AUTHENTICATION_BACKENDS=["django.contrib.auth.backends.ModelBackend"])
class TestFido2GeneralAuthenticationBackend(TestCase):
    """Test `Fido2GeneralAuthenticationBackend` class."""

    backend = Fido2GeneralAuthenticationBackend()

    server = Fido2Server(PublicKeyCredentialRpEntity(HOSTNAME, HOSTNAME))

    state = {"challenge": AUTHENTICATION_CHALLENGE, "user_verification": UserVerificationRequirement.PREFERRED}
    fido2_response = {
        "client_data": CollectedClientData(base64.b64decode(AUTHENTICATION_CLIENT_DATA)),
        "credential_id": base64.b64decode(CREDENTIAL_ID),
        "authenticator_data": AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
        "signature": base64.b64decode(SIGNATURE),
    }

    def setUp(self):
        self.user = User.objects.create_user(USERNAME, password=PASSWORD)
        self.device = Authenticator.objects.create(
            user=self.user, credential_id_data=CREDENTIAL_ID, attestation_data=ATTESTATION_OBJECT
        )

    def test_authenticate(self):
        authenticated_user = self.backend.authenticate(
            sentinel.request, USERNAME, PASSWORD, self.server, self.state, self.fido2_response
        )
        self.assertEqual(authenticated_user, self.user)
        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 152)], transform=tuple
        )

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_aauthenticate(self):
        authenticated_user = await self.backend.aauthenticate(
            sentinel.request, USERNAME, PASSWORD, self.server, self.state, self.fido2_response
        )
        self.assertEqual(authenticated_user, self.user)
        self.assertQuerySetEqual(
            [a async for a in Authenticator.objects.values_list("user", "counter")],
            [(self.user.pk, 152)],
            transform=tuple,
        )

    def test_authenticate_wrong_password(self):
        authenticated_user = self.backend.authenticate(
            sentinel.request, USERNAME, "wrong_password", self.server, self.state, self.fido2_response
        )
        self.assertEqual(authenticated_user, None)
        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 0)], transform=tuple
        )

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_aauthenticate_wrong_password(self):
        authenticated_user = await self.backend.aauthenticate(
            sentinel.request, USERNAME, "wrong_password", self.server, self.state, self.fido2_response
        )
        self.assertEqual(authenticated_user, None)
        self.assertQuerySetEqual(
            [a async for a in Authenticator.objects.values_list("user", "counter")],
            [(self.user.pk, 0)],
            transform=tuple,
        )


class TestIsFidoBackendUsed(SimpleTestCase):
    @override_settings(AUTHENTICATION_BACKENDS=["django_fido.backends.Fido2AuthenticationBackend"])
    def test_is_used(self):
        self.assertTrue(is_fido_backend_used())

    @override_settings(AUTHENTICATION_BACKENDS=["django.contrib.auth.backends.ModelBackend"])
    def test_is_not_used(self):
        self.assertFalse(is_fido_backend_used())


class TestFido2PasswordlessAuthenticationBackend(TestCase):
    """Test `Fido2AuthenticationBackend` class."""

    backend = Fido2PasswordlessAuthenticationBackend()

    server = Fido2Server(PublicKeyCredentialRpEntity(HOSTNAME, HOSTNAME))

    state = {"challenge": AUTHENTICATION_CHALLENGE, "user_verification": UserVerificationRequirement.PREFERRED}
    fido2_response = {
        "client_data": CollectedClientData(base64.b64decode(AUTHENTICATION_CLIENT_DATA)),
        "credential_id": base64.b64decode(CREDENTIAL_ID),
        "authenticator_data": AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
        "signature": base64.b64decode(SIGNATURE),
        "user_handle": USER_HANDLE,
    }

    def setUp(self):
        self.user = User.objects.create_user(USERNAME)
        self.device = Authenticator.objects.create(
            user=self.user,
            user_handle=USER_HANDLE,
            credential_id_data=CREDENTIAL_ID,
            attestation_data=ATTESTATION_OBJECT,
        )

    def test_authenticate(self):
        authenticated_user = self.backend.authenticate(
            sentinel.request, None, self.server, self.state, self.fido2_response
        )

        self.assertEqual(authenticated_user, self.user)
        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 152)], transform=tuple
        )

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_aauthenticate(self):
        authenticated_user = await self.backend.aauthenticate(
            sentinel.request, None, self.server, self.state, self.fido2_response
        )

        self.assertEqual(authenticated_user, self.user)
        self.assertQuerySetEqual(
            [a async for a in Authenticator.objects.values_list("user", "counter")],
            [(self.user.pk, 152)],
            transform=tuple,
        )

    def test_authenticate_wrong_counter(self):
        self.device.counter = 160
        self.device.save()
        request = RequestFactory().get("/dummy/")
        request._messages = CookieStorage(request)

        self.assertRaisesMessage(
            PermissionDenied,
            "Counter didn't increase.",
            self.backend.authenticate,
            request,
            None,
            self.server,
            self.state,
            self.fido2_response,
        )

        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 160)], transform=tuple
        )

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_aauthenticate_wrong_counter(self):
        self.device.counter = 160
        await self.device.asave()
        request = RequestFactory().get("/dummy/")
        request._messages = CookieStorage(request)

        with self.assertRaisesMessage(PermissionDenied, "Counter didn't increase."):
            await self.backend.aauthenticate(request, None, self.server, self.state, self.fido2_response)

        self.assertQuerySetEqual(
            [a async for a in Authenticator.objects.values_list("user", "counter")],
            [(self.user.pk, 160)],
            transform=tuple,
        )

    def test_authenticate_invalid_response(self):
        fido2_response = {
            "client_data": CollectedClientData(base64.b64decode(AUTHENTICATION_CLIENT_DATA)),
            "credential_id": base64.b64decode(CREDENTIAL_ID),
            "authenticator_data": AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
            "user_handle": USER_HANDLE_B64,
            "signature": b"INVALID",
        }
        self.assertIsNone(self.backend.authenticate(sentinel.request, None, self.server, self.state, fido2_response))

    @skipIf(django.VERSION < (5, 2), "Old django does not support async auth")
    async def test_aauthenticate_invalid_response(self):
        fido2_response = {
            "client_data": CollectedClientData(base64.b64decode(AUTHENTICATION_CLIENT_DATA)),
            "credential_id": base64.b64decode(CREDENTIAL_ID),
            "authenticator_data": AuthenticatorData(base64.b64decode(AUTHENTICATOR_DATA)),
            "user_handle": USER_HANDLE_B64,
            "signature": b"INVALID",
        }
        self.assertIsNone(
            await self.backend.aauthenticate(sentinel.request, None, self.server, self.state, fido2_response)
        )

    def test_mark_device_used(self):
        self.backend.mark_device_used(self.device, 42)

        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 42)], transform=tuple
        )

    def test_mark_device_used_equal(self):
        # Test device returned the same counter.
        self.device.counter = 42
        self.device.save()

        self.assertRaisesMessage(ValueError, "Counter didn't increase.", self.backend.mark_device_used, self.device, 42)

        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 42)], transform=tuple
        )

    def test_mark_device_used_unsupported(self):
        # Test device is allowed if counter is unsupported
        self.device.counter = 0
        self.device.save()

        self.backend.mark_device_used(self.device, 0)

        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 0)], transform=tuple
        )

    def test_mark_device_used_decrease(self):
        # Test device returned lower counter.
        self.device.counter = 42
        self.device.save()

        self.assertRaisesMessage(ValueError, "Counter didn't increase.", self.backend.mark_device_used, self.device, 41)

        self.assertQuerySetEqual(
            Authenticator.objects.values_list("user", "counter"), [(self.user.pk, 42)], transform=tuple
        )

    def test_get_user(self):
        self.assertEqual(self.backend.get_user(self.user.pk), self.user)

    def test_get_user_unknown(self):
        self.assertIsNone(self.backend.get_user(42))
