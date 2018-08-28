"""Test `django_fido.views` module."""
from __future__ import unicode_literals

import base64
import json

from django.contrib.auth import get_user, get_user_model
from django.core.exceptions import NON_FIELD_ERRORS
from django.test import TestCase, override_settings
from django.urls import reverse, reverse_lazy
from fido2.server import USER_VERIFICATION
from fido2.utils import websafe_decode

from django_fido.constants import (AUTHENTICATION_REQUEST_SESSION_KEY, AUTHENTICATION_USER_SESSION_KEY,
                                   FIDO2_REQUEST_SESSION_KEY)
from django_fido.models import Authenticator, U2fDevice

from .data import (ATTESTATION_OBJECT, CREDENTIAL_DATA, CREDENTIAL_ID, HOSTNAME, REGISTRATION_CHALLENGE,
                   REGISTRATION_CLIENT_DATA, USER_FIRST_NAME, USER_FULL_NAME, USER_LAST_NAME, USERNAME)
from .utils import TEMPLATES

User = get_user_model()


@override_settings(ROOT_URLCONF='django_fido.tests.urls')
class TestFido2RegistrationRequestView(TestCase):
    """Test `Fido2RegistrationRequestView` class."""

    url = reverse_lazy('django_fido:registration_request')

    def setUp(self):
        self.user = User.objects.create_user(USERNAME, first_name=USER_FIRST_NAME, last_name=USER_LAST_NAME)

    def test_anonymous(self):
        with self.settings(LOGIN_URL='/login/'):
            response = self.client.get(self.url)

        self.assertRedirects(response, '/login/?next={}'.format(self.url), fetch_redirect_response=False)

    def _get_fido2_request(self, challenge, credentials):
        credential_params = [{'alg': -7, 'type': 'public-key'}, {'alg': -8, 'type': 'public-key'},
                             {'alg': -37, 'type': 'public-key'}, {'alg': -257, 'type': 'public-key'}]
        return {'publicKey': {'rp': {'id': HOSTNAME, 'name': HOSTNAME},
                              'user': {'displayName': USER_FULL_NAME, 'id': USERNAME, 'name': USERNAME},
                              'timeout': 30000,
                              'authenticatorSelection': {'requireResidentKey': False, 'userVerification': 'preferred'},
                              'challenge': base64.b64encode(challenge).decode('utf-8'),
                              'pubKeyCredParams': credential_params,
                              'attestation': 'none',
                              'excludeCredentials': credentials}}

    def test_get(self):
        self.client.force_login(self.user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        # Check response
        state = self.client.session[FIDO2_REQUEST_SESSION_KEY]
        challenge = websafe_decode(state['challenge'])
        self.assertEqual(response.json(), self._get_fido2_request(challenge, []))

    def test_get_registered_keys(self):
        Authenticator.objects.create(user=self.user, credential_data=CREDENTIAL_DATA)
        self.client.force_login(self.user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        # Check response contains the same request as session
        state = self.client.session[FIDO2_REQUEST_SESSION_KEY]
        challenge = websafe_decode(state['challenge'])
        credentials = [{'id': CREDENTIAL_ID, 'type': 'public-key'}]
        self.assertEqual(response.json(), self._get_fido2_request(challenge, credentials))


@override_settings(ROOT_URLCONF='django_fido.tests.urls', TEMPLATES=TEMPLATES)
class TestFido2RegistrationView(TestCase):
    """Test `Fido2RegistrationView` class."""

    url = reverse_lazy('django_fido:registration')
    state = {'challenge': REGISTRATION_CHALLENGE, 'user_verification': USER_VERIFICATION.PREFERRED}

    def setUp(self):
        self.user = User.objects.create_user(USERNAME)

    def test_anonymous(self):
        with self.settings(LOGIN_URL='/login/'):
            response = self.client.get(self.url)

        self.assertRedirects(response, '/login/?next={}'.format(self.url), fetch_redirect_response=False)

    def test_get(self):
        self.client.force_login(self.user)

        response = self.client.get(self.url)

        self.assertContains(response, 'Register a new FIDO 2 authenticator')

    def test_post(self):
        self.client.force_login(self.user)
        session = self.client.session
        session[FIDO2_REQUEST_SESSION_KEY] = self.state
        session.save()

        response = self.client.post(self.url,
                                    {'client_data': REGISTRATION_CLIENT_DATA, 'attestation': ATTESTATION_OBJECT})

        self.assertRedirects(response, reverse('django_fido:registration_done'))
        queryset = Authenticator.objects.values_list('user__pk', 'credential_data', 'counter')
        key_data = (self.user.pk, CREDENTIAL_DATA, 0)
        self.assertQuerysetEqual(queryset, [key_data], transform=tuple)
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)

    def test_post_no_session(self):
        self.client.force_login(self.user)

        response = self.client.post(self.url,
                                    {'client_data': REGISTRATION_CLIENT_DATA, 'attestation': ATTESTATION_OBJECT})

        self.assertContains(response, 'Register a new FIDO 2 authenticator')
        self.assertEqual(response.context['form'].errors, {NON_FIELD_ERRORS: ['Registration request not found.']})
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)

    def test_post_invalid_response(self):
        self.client.force_login(self.user)
        session = self.client.session
        session[FIDO2_REQUEST_SESSION_KEY] = self.state
        session.save()

        client_data = base64.b64encode(json.dumps({"type": "invalid"}).encode()).decode()
        response = self.client.post(self.url, {'client_data': client_data, 'attestation': ATTESTATION_OBJECT})

        self.assertContains(response, 'Register a new FIDO 2 authenticator')
        self.assertEqual(response.context['form'].errors, {NON_FIELD_ERRORS: ['Registration failed.']})
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)


@override_settings(ROOT_URLCONF='django_fido.tests.urls')
class TestU2fAuthenticationRequestView(TestCase):
    """Test `U2fAuthenticationRequestView` class."""

    url = reverse_lazy('django_fido:u2f_authentication_request')
    session_key = AUTHENTICATION_REQUEST_SESSION_KEY

    def test_no_user(self):
        with self.settings(LOGIN_URL='/login/'):
            response = self.client.get(self.url)

        self.assertRedirects(response, '/login/', fetch_redirect_response=False)

    def test_get(self):
        user = User.objects.create_user('kryten')
        U2fDevice.objects.create(user=user, version='42', key_handle='Left nipple', public_key='Yes', app_id='FM Radio',
                                 transports=['ble'])
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = user.pk
        session.save()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        # Check request structure
        u2f_request = self.client.session[self.session_key]
        self.assertEqual(u2f_request['appId'], 'http://testserver')
        registered_key = {'keyHandle': 'Left nipple', 'publicKey': 'Yes', 'appId': 'FM Radio', 'version': '42',
                          'transports': ['ble']}
        self.assertEqual(u2f_request['registeredKeys'], [registered_key])
        self.assertIn('challenge', u2f_request)
        # Check response contains the same request as session (except for the public key).
        public_registered_key = {'keyHandle': 'Left nipple', 'appId': 'FM Radio', 'version': '42',
                                 'transports': ['ble']}
        response_data = {'appId': 'http://testserver', 'registeredKeys': [public_registered_key],
                         'challenge': u2f_request['challenge']}
        self.assertEqual(response.json(), response_data)

    def test_get_no_keys(self):
        user = User.objects.create_user('kryten')
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = user.pk
        session.save()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': "Can't create U2F request: Must have at least one RegisteredKey"})
        self.assertNotIn(self.session_key, self.client.session)


@override_settings(ROOT_URLCONF='django_fido.tests.urls', TEMPLATES=TEMPLATES,
                   AUTHENTICATION_BACKENDS=['django_fido.backends.U2fAuthenticationBackend'])
class TestU2fAuthenticationView(TestCase):
    """Test `U2fAuthenticationView` class."""

    url = reverse_lazy('django_fido:authentication')
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

    def test_no_user(self):
        with self.settings(LOGIN_URL='/login/'):
            response = self.client.get(self.url)

        self.assertRedirects(response, '/login/', fetch_redirect_response=False)

    def test_get(self):
        user = User.objects.create_user('kryten')
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = user.pk
        session.save()

        response = self.client.get(self.url)

        self.assertContains(response, 'Authenticate Universal 2nd Factor (U2F) key')

    def test_post(self):
        user = User.objects.create_user('kryten')
        U2fDevice.objects.create(user=user, version='U2F_V2', key_handle=self.key_handle, public_key=self.public_key)
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = user.pk
        session[AUTHENTICATION_REQUEST_SESSION_KEY] = self.u2f_request
        session.save()

        with self.settings(LOGIN_REDIRECT_URL='/redirect/'):
            response = self.client.post(self.url, {'u2f_response': json.dumps(self.u2f_response)})

        self.assertRedirects(response, '/redirect/', fetch_redirect_response=False)
        self.assertEqual(get_user(self.client), user)
        self.assertQuerysetEqual(U2fDevice.objects.values_list('user', 'counter'), [(user.pk, 20)], transform=tuple)
        self.assertNotIn(AUTHENTICATION_REQUEST_SESSION_KEY, self.client.session)
        self.assertNotIn(AUTHENTICATION_USER_SESSION_KEY, self.client.session)

    def test_post_no_session(self):
        # Test U2F request is not stored in session
        user = User.objects.create_user('kryten')
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = user.pk
        session.save()

        response = self.client.post(self.url, {'u2f_response': 'null'})

        self.assertContains(response, 'Authenticate Universal 2nd Factor (U2F) key')
        self.assertEqual(response.context['form'].errors, {NON_FIELD_ERRORS: ['Authentication request not found.']})
        self.assertNotIn(AUTHENTICATION_REQUEST_SESSION_KEY, self.client.session)
        self.assertEqual(self.client.session[AUTHENTICATION_USER_SESSION_KEY], user.pk)

    def test_post_invalid_response(self):
        user = User.objects.create_user('kryten')
        self.client.force_login(user)
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = user.pk
        session[AUTHENTICATION_REQUEST_SESSION_KEY] = self.u2f_request
        session.save()

        response = self.client.post(self.url, {'u2f_response': 'null'})

        self.assertContains(response, 'Authenticate Universal 2nd Factor (U2F) key')
        self.assertEqual(response.context['form'].errors, {NON_FIELD_ERRORS: ['Authentication failed.']})
        self.assertNotIn(AUTHENTICATION_REQUEST_SESSION_KEY, self.client.session)
        self.assertEqual(self.client.session[AUTHENTICATION_USER_SESSION_KEY], user.pk)
