"""Test `django_fido.views` module."""
from __future__ import unicode_literals

import json

from django.contrib.auth import get_user, get_user_model
from django.core.exceptions import NON_FIELD_ERRORS
from django.test import TestCase, override_settings
from django.urls import reverse, reverse_lazy

from django_fido.models import U2fDevice
from django_fido.views import (AUTHENTICATION_REQUEST_SESSION_KEY, AUTHENTICATION_USER_SESSION_KEY,
                               REGISTRATION_REQUEST_SESSION_KEY)

from .utils import TEMPLATES

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


@override_settings(ROOT_URLCONF='django_fido.tests.urls', TEMPLATES=TEMPLATES)
class TestU2fRegistrationView(TestCase):
    """Test `U2fRegistrationView` class."""

    url = reverse_lazy('django_fido:registration')
    u2f_request = {'appId': 'http://testserver', 'registeredKeys': [],
                   'registerRequests': [{'challenge': 'Listers_underpants', 'version': 'U2F_V2'}]}
    u2f_response = {
        'registrationData': ('BQR4cOSm5qgX1VDRogGXslsVW6wbVI04ccE3g3D5nBvITulx8ad26J6fzhFR5A-tNYUzCB-nEXmC1dagSMidDXiFQ'
                             'ImCDvzeNu-hzQ_1-SFfEj-xYvW0HMXSHjh7tq_cH-0bhbqfcsAfl8FNfGJGNAlrB_O9Pqm2XcO6uSbs8hOBqkEwgg'
                             'JEMIIBLqADAgECAgR4wN8OMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWF'
                             'sIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAwwfWXViaWNvIFUy'
                             'RiBFRSBTZXJpYWwgMjAyNTkwNTkzNDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLW4cVyD_f4OoVxFd6yFjfSMF'
                             '2_eh53K9Lg9QNMg8m-t5iX89_XIr9g1GPjbniHsCDsYRYDHF-xKRwuWim-6P2-jOzA5MCIGCSsGAQQBgsQKAgQVMS'
                             '4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMAsGCSqGSIb3DQEBCwOCAQEAPvar9kqRawv'
                             '5lJON3JU04FRAAmhWeKcsQ6er5l2QZf9h9FHOijru2GaJ0ZC5UK8AelTRMe7wb-JrTqe7PjK3kgWl36dgBDRT40r4'
                             'RMN81KhfjFwthw4KKLK37UQCQf2zeSsgdrDhivqbQy7u_CZYugkFxBskqTxuyLum1W8z6NZT189r1QFUVaJll0D33'
                             'MUcwDFgnNA-ps3pOZ7KCHYykHY_tMjQD1aQaaElSQBq67BqIaIU5JmYN7Qp6B1-VtM6VJLdOhYcgpOVQIGqfu90nD'
                             'pWPb3X26OVzEc-RGltQZGFwkN6yDrAZMHL5HIn_3obd8fV6gw2fUX2ML2ZjVmybjBEAiBTOUwY12wm2TrRMsAs-EK'
                             'PacouX_X7bOEz6vnLk03JtAIgaqR9H4lOx4JBeQb-xwLPz1shKfxwD1pVY67X-m8ACEI'),
        'clientData': ('eyAiY2hhbGxlbmdlIjogIkxpc3RlcnNfdW5kZXJwYW50cyIsICJvcmlnaW4iOiAiaHR0cDpcL1wvbW9qZWlkLnZ6aW1hIiw'
                       'gInR5cCI6ICJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIgfQ'),
        'version': 'U2F_V2'}

    attestation = (
        'MIICRDCCAS6gAwIBAgIEeMDfDjALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIB'
        'cNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDIwMjU5MDU5MzQwWTATBgcq'
        'hkjOPQIBBggqhkjOPQMBBwNCAAS1uHFcg/3+DqFcRXeshY30jBdv3oedyvS4PUDTIPJvreYl/Pf1yK/YNRj4254h7Ag7GEWAxxfsSkcLlopvuj'
        '9vozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDALBgkqhkiG9w0BAQsDggEBAD72'
        'q/ZKkWsL+ZSTjdyVNOBUQAJoVninLEOnq+ZdkGX/YfRRzoo67thmidGQuVCvAHpU0THu8G/ia06nuz4yt5IFpd+nYAQ0U+NK+ETDfNSoX4xcLY'
        'cOCiiyt+1EAkH9s3krIHaw4Yr6m0Mu7vwmWLoJBcQbJKk8bsi7ptVvM+jWU9fPa9UBVFWiZZdA99zFHMAxYJzQPqbN6Tmeygh2MpB2P7TI0A9W'
        'kGmhJUkAauuwaiGiFOSZmDe0KegdflbTOlSS3ToWHIKTlUCBqn7vdJw6Vj2919ujlcxHPkRpbUGRhcJDesg6wGTBy+RyJ/96G3fH1eoMNn1F9j'
        'C9mY1Zsm4=')

    def test_anonymous(self):
        with self.settings(LOGIN_URL='/login/'):
            response = self.client.get(self.url)

        self.assertRedirects(response, '/login/?next={}'.format(self.url), fetch_redirect_response=False)

    def test_get(self):
        user = User.objects.create_user('kryten')
        self.client.force_login(user)

        response = self.client.get(self.url)

        self.assertContains(response, 'Register Universal 2nd Factor (U2F) key')

    def test_post(self):
        user = User.objects.create_user('kryten')
        self.client.force_login(user)
        session = self.client.session
        session[REGISTRATION_REQUEST_SESSION_KEY] = self.u2f_request
        session.save()

        response = self.client.post(self.url, {'u2f_response': json.dumps(self.u2f_response)})

        self.assertRedirects(response, reverse('django_fido:registration_done'))
        queryset = U2fDevice.objects.values_list('user__pk', 'version', 'key_handle', 'public_key', 'app_id',
                                                 'raw_transports', 'attestation')
        key_data = (user.pk, 'U2F_V2',
                    'iYIO_N4276HND_X5IV8SP7Fi9bQcxdIeOHu2r9wf7RuFup9ywB-XwU18YkY0CWsH870-qbZdw7q5JuzyE4GqQQ',
                    'BHhw5KbmqBfVUNGiAZeyWxVbrBtUjThxwTeDcPmcG8hO6XHxp3bonp_OEVHkD601hTMIH6cReYLV1qBIyJ0NeIU',
                    'http://testserver', 'usb', self.attestation)
        self.assertQuerysetEqual(queryset, [key_data], transform=tuple)
        self.assertNotIn(REGISTRATION_REQUEST_SESSION_KEY, self.client.session)

    def test_post_no_session(self):
        user = User.objects.create_user('kryten')
        self.client.force_login(user)

        response = self.client.post(self.url, {'u2f_response': 'null'})

        self.assertContains(response, 'Register Universal 2nd Factor (U2F) key')
        self.assertEqual(response.context['form'].errors, {NON_FIELD_ERRORS: ['Registration request not found.']})
        self.assertNotIn(REGISTRATION_REQUEST_SESSION_KEY, self.client.session)

    def test_post_invalid_response(self):
        user = User.objects.create_user('kryten')
        self.client.force_login(user)
        session = self.client.session
        session[REGISTRATION_REQUEST_SESSION_KEY] = self.u2f_request
        session.save()

        response = self.client.post(self.url, {'u2f_response': 'null'})

        self.assertContains(response, 'Register Universal 2nd Factor (U2F) key')
        self.assertEqual(response.context['form'].errors, {NON_FIELD_ERRORS: ['Registration failed.']})
        self.assertNotIn(REGISTRATION_REQUEST_SESSION_KEY, self.client.session)


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
