"""Test `django_fido.views` module."""
from __future__ import unicode_literals

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse_lazy

from django_fido.models import U2fDevice
from django_fido.views import REGISTRATION_REQUEST_SESSION_KEY

User = get_user_model()


@override_settings(ROOT_URLCONF='django_fido.tests.urls')
class TestU2fRegistrationRequestView(TestCase):
    """Test `U2fRegistrationRequestView` class."""

    url = reverse_lazy('django_fido:u2f_registration_request')
    session_key = REGISTRATION_REQUEST_SESSION_KEY

    def test_anonymous(self):
        with self.settings(LOGIN_URL='/login/'):
            response = self.client.get(self.url)

        self.assertRedirects(response, '/login/?next={}'.format(self.url), fetch_redirect_response=False)

    def test_get(self):
        user = User.objects.create_user('kryten')
        self.client.force_login(user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        # Check response contains the same request as session
        u2f_request = self.client.session[self.session_key]
        self.assertEqual(response.json(), u2f_request)
        # Check request structure
        self.assertEqual(u2f_request['appId'], 'http://testserver')
        self.assertEqual(u2f_request['registeredKeys'], [])
        self.assertEqual(u2f_request['registerRequests'][0]['version'], 'U2F_V2')
        self.assertIn('challenge', u2f_request['registerRequests'][0])

    def test_get_registered_keys(self):
        user = User.objects.create_user('kryten')
        U2fDevice.objects.create(user=user, version='42', key_handle='Left nipple', public_key='Yes', app_id='FM Radio',
                                 transports=['ble'])
        self.client.force_login(user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        # Check request structure
        registered_key = {'keyHandle': 'Left nipple', 'publicKey': 'Yes', 'appId': 'FM Radio', 'version': '42',
                          'transports': ['ble']}
        u2f_request = self.client.session[self.session_key]
        self.assertEqual(u2f_request['appId'], 'http://testserver')
        self.assertEqual(u2f_request['registeredKeys'], [registered_key])
        self.assertEqual(u2f_request['registerRequests'][0]['version'], 'U2F_V2')
        self.assertIn('challenge', u2f_request['registerRequests'][0])
        # Check response contains the same request as session (except for the public key).
        public_registered_key = {'keyHandle': 'Left nipple', 'appId': 'FM Radio', 'version': '42',
                                 'transports': ['ble']}
        response_data = {'appId': 'http://testserver', 'registerRequests': u2f_request['registerRequests'],
                         'registeredKeys': [public_registered_key]}
        self.assertEqual(response.json(), response_data)
