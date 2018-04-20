"""Test `django_fido.backends` module."""
from __future__ import unicode_literals

from django.contrib.auth import get_user_model
from django.contrib.messages.storage.cookie import CookieStorage
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory, TestCase
from mock import sentinel

from django_fido.backends import U2fAuthenticationBackend
from django_fido.models import U2fDevice

User = get_user_model()


class TestU2fAuthenticationBackend(TestCase):
    """Test `U2fAuthenticationBackend` class."""

    backend = U2fAuthenticationBackend()

    # Valid U2F data
    key_handle = 'iYIO_N4276HND_X5IV8SP7Fi9bQcxdIeOHu2r9wf7RuFup9ywB-XwU18YkY0CWsH870-qbZdw7q5JuzyE4GqQQ'
    public_key = 'BHhw5KbmqBfVUNGiAZeyWxVbrBtUjThxwTeDcPmcG8hO6XHxp3bonp_OEVHkD601hTMIH6cReYLV1qBIyJ0NeIU'
    registered_key = {'publicKey': public_key, 'keyHandle': key_handle, 'version': 'U2F_V2', 'transports': ['usb'],
                      'appId': 'http://testserver'}
    u2f_request = {'appId': 'http://testserver',
                   'challenge': 'Listers_underpants',
                   'registeredKeys': [registered_key]}
    u2f_response = {
        'signatureData': ('AQAAABQwRQIhAOsMkVTyzVdHUeOvNJpCzUZjsHIs8vCJlmrwEwH90tR4AiAJHH-KB7OjUAoEemUkyiiyYd4QMK4YmTTr'
                          'dqCzn9U8YQ'),
        'clientData': ('eyAiY2hhbGxlbmdlIjogIkxpc3RlcnNfdW5kZXJwYW50cyIsICJvcmlnaW4iOiAiaHR0cDpcL1wvdGVzdHNlcnZlciIsICJ'
                       '0eXAiOiAibmF2aWdhdG9yLmlkLmdldEFzc2VydGlvbiIgfQ'),
        'keyHandle': key_handle}

    def test_authenticate(self):
        user = User.objects.create_user('kryten')
        U2fDevice.objects.create(user=user, version='U2F_V2', key_handle=self.key_handle, public_key=self.public_key)

        authenticated_user = self.backend.authenticate(sentinel.request, user, self.u2f_request, self.u2f_response)

        self.assertEqual(authenticated_user, user)
        self.assertQuerysetEqual(U2fDevice.objects.values_list('user', 'counter'), [(user.pk, 20)], transform=tuple)

    def test_authenticate_wrong_counter(self):
        user = User.objects.create_user('kryten')
        U2fDevice.objects.create(user=user, version='U2F_V2', key_handle=self.key_handle, public_key=self.public_key,
                                 counter=42)
        request = RequestFactory().get('/dummy/')
        request._messages = CookieStorage(request)

        self.assertRaisesMessage(PermissionDenied, "Counter didn't increase.",
                                 self.backend.authenticate, request, user, self.u2f_request, self.u2f_response)

        self.assertQuerysetEqual(U2fDevice.objects.values_list('user', 'counter'), [(user.pk, 42)], transform=tuple)

    def test_authenticate_invalid_request(self):
        self.assertIsNone(self.backend.authenticate(sentinel.request, sentinel.user, {}, self.u2f_response))

    def test_authenticate_invalid_response(self):
        self.assertIsNone(self.backend.authenticate(sentinel.request, sentinel.user, self.u2f_request, {}))

    def test_mark_device_used(self):
        user = User.objects.create_user('kryten')
        u2f_device = U2fDevice.objects.create(user=user, version='U2F_V2', key_handle='Left nipple', public_key='Turn')

        self.backend.mark_device_used(u2f_device, 42)

        self.assertQuerysetEqual(U2fDevice.objects.values_list('user', 'counter'), [(user.pk, 42)], transform=tuple)

    def test_mark_device_used_equal(self):
        # Test device returned the same counter.
        user = User.objects.create_user('kryten')
        u2f_device = U2fDevice.objects.create(user=user, version='U2F_V2', key_handle='Left nipple', public_key='Turn',
                                              counter=42)

        self.assertRaisesMessage(ValueError, "Counter didn't increase.", self.backend.mark_device_used, u2f_device, 42)

        self.assertQuerysetEqual(U2fDevice.objects.values_list('user', 'counter'), [(user.pk, 42)], transform=tuple)

    def test_mark_device_used_decrease(self):
        # Test device returned lower counter.
        user = User.objects.create_user('kryten')
        u2f_device = U2fDevice.objects.create(user=user, version='U2F_V2', key_handle='Left nipple', public_key='Turn',
                                              counter=42)

        self.assertRaisesMessage(ValueError, "Counter didn't increase.", self.backend.mark_device_used, u2f_device, 41)

        self.assertQuerysetEqual(U2fDevice.objects.values_list('user', 'counter'), [(user.pk, 42)], transform=tuple)

    def test_get_user(self):
        user = User.objects.create_user('kryten')
        self.assertEqual(self.backend.get_user(user.pk), user)

    def test_get_user_unknown(self):
        self.assertIsNone(self.backend.get_user(42))
