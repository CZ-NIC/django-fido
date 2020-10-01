"""Test `django_fido.views` module."""
import base64
import json

import fido2
from django.contrib.auth import get_user, get_user_model
from django.core.exceptions import NON_FIELD_ERRORS
from django.test import TestCase, override_settings
from django.urls import reverse, reverse_lazy
from fido2.utils import websafe_decode

from django_fido.constants import AUTHENTICATION_USER_SESSION_KEY, FIDO2_REQUEST_SESSION_KEY
from django_fido.models import Authenticator

from .data import (ATTESTATION_OBJECT, ATTESTATION_OBJECT_BOGUS, ATTESTATION_OBJECT_U2F_MALFORMED,
                   AUTHENTICATION_CHALLENGE, AUTHENTICATION_CLIENT_DATA, AUTHENTICATOR_DATA, CREDENTIAL_ID, HOSTNAME,
                   PASSWORD, REGISTRATION_CHALLENGE, REGISTRATION_CLIENT_DATA, SIGNATURE, USER_FIRST_NAME,
                   USER_FULL_NAME, USER_LAST_NAME, USERNAME)
from .utils import TEMPLATES

try:
    from fido2.webauthn import UserVerificationRequirement
except ImportError:
    from fido2.server import USER_VERIFICATION as UserVerificationRequirement

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
        rp_data = {
            'id': HOSTNAME,
            'name': HOSTNAME,
        }
        fido2_request = {'publicKey': {
            'rp': rp_data,
            'user': {'displayName': USER_FULL_NAME, 'id': USERNAME, 'name': USERNAME},
            'timeout': 30000,
            'challenge': base64.b64encode(challenge).decode('utf-8'),
            'pubKeyCredParams': credential_params,
            'attestation': 'none',
            'excludeCredentials': credentials,
        }}
        if fido2.__version__ < '0.8':
            fido2_request['publicKey']['authenticatorSelection'] = {'requireResidentKey': False,
                                                                    'userVerification': 'preferred'}
        return fido2_request

    def test_get(self):
        self.client.force_login(self.user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        # Check response
        state = self.client.session[FIDO2_REQUEST_SESSION_KEY]
        challenge = websafe_decode(state['challenge'])
        self.assertEqual(response.json(), self._get_fido2_request(challenge, []))

    def test_get_registered_keys(self):
        Authenticator.objects.create(user=self.user, attestation_data=ATTESTATION_OBJECT)
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
    state = {'challenge': REGISTRATION_CHALLENGE, 'user_verification': UserVerificationRequirement.PREFERRED}

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
        queryset = Authenticator.objects.values_list('user__pk', 'credential_id_data', 'attestation_data', 'counter')
        key_data = (self.user.pk, CREDENTIAL_ID, ATTESTATION_OBJECT, 0)
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

    def test_post_invalid_format(self):
        self.client.force_login(self.user)
        session = self.client.session
        session[FIDO2_REQUEST_SESSION_KEY] = self.state
        session.save()

        url = reverse_lazy('registration_direct')
        response = self.client.post(url, {'client_data': REGISTRATION_CLIENT_DATA,
                                          'attestation': ATTESTATION_OBJECT_BOGUS})

        self.assertContains(response, 'Register a new FIDO 2 authenticator')
        self.assertEqual(response.context['form'].errors,
                         {NON_FIELD_ERRORS: ['Security key is not supported because it cannot be identified.']})
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)

    def test_post_invalid_data(self):
        self.client.force_login(self.user)
        session = self.client.session
        session[FIDO2_REQUEST_SESSION_KEY] = self.state
        session.save()

        url = reverse_lazy('registration_direct')
        response = self.client.post(url, {'client_data': REGISTRATION_CLIENT_DATA,
                                          'attestation': ATTESTATION_OBJECT_U2F_MALFORMED})

        self.assertContains(response, 'Register a new FIDO 2 authenticator')
        self.assertEqual(response.context['form'].errors,
                         {NON_FIELD_ERRORS: ['Registration failed, incorrect data from security key.']})
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)


@override_settings(ROOT_URLCONF='django_fido.tests.urls')
class TestFido2AuthenticationRequestView(TestCase):
    """Test `Fido2AuthenticationRequestView` class."""

    url = reverse_lazy('django_fido:authentication_request')

    def setUp(self):
        self.user = User.objects.create_user(USERNAME)

    def test_no_user(self):
        with self.settings(LOGIN_URL='/login/'):
            response = self.client.get(self.url)

        self.assertRedirects(response, '/login/', fetch_redirect_response=False)

    @override_settings(DJANGO_FIDO_TWO_STEP_AUTH=True)
    def test_get(self):
        Authenticator.objects.create(user=self.user, attestation_data=ATTESTATION_OBJECT)
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = self.user.pk
        session.save()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        # Check response
        state = self.client.session[FIDO2_REQUEST_SESSION_KEY]
        challenge = websafe_decode(state['challenge'])
        fido2_request = {
            'publicKey': {'rpId': 'testserver',
                          'challenge': base64.b64encode(challenge).decode('utf-8'),
                          'allowCredentials': [{'id': CREDENTIAL_ID, 'type': 'public-key'}],
                          'timeout': 30000}}
        if fido2.__version__ < '0.8':
            fido2_request['publicKey']['userVerification'] = 'preferred'
        self.assertEqual(response.json(), fido2_request)

    @override_settings(DJANGO_FIDO_TWO_STEP_AUTH=True)
    def test_get_no_keys(self):
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = self.user.pk
        session.save()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'error_code': 'NoAuthenticatorsError',
            'message': "Can't create FIDO 2 authentication request, no authenticators found.",
            'error': "Can't create FIDO 2 authentication request, no authenticators found.",
        })
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)

    @override_settings(DJANGO_FIDO_TWO_STEP_AUTH=False)
    def test_get_by_username(self):
        Authenticator.objects.create(user=self.user, attestation_data=ATTESTATION_OBJECT)

        response = self.client.get(self.url, data={'username': self.user.username})

        self.assertEqual(response.status_code, 200)
        # Check response
        state = self.client.session[FIDO2_REQUEST_SESSION_KEY]
        challenge = websafe_decode(state['challenge'])
        fido2_request = {
            'publicKey': {'rpId': 'testserver',
                          'challenge': base64.b64encode(challenge).decode('utf-8'),
                          'allowCredentials': [{'id': CREDENTIAL_ID, 'type': 'public-key'}],
                          'timeout': 30000}}
        if fido2.__version__ < '0.8':
            fido2_request['publicKey']['userVerification'] = 'preferred'
        self.assertEqual(response.json(), fido2_request)


@override_settings(ROOT_URLCONF='django_fido.tests.urls', TEMPLATES=TEMPLATES,
                   AUTHENTICATION_BACKENDS=['django_fido.backends.Fido2AuthenticationBackend'])
class TestFido2AuthenticationView(TestCase):
    """Test `Fido2AuthenticationView` class."""

    url = reverse_lazy('django_fido:authentication')
    state = {'challenge': AUTHENTICATION_CHALLENGE, 'user_verification': UserVerificationRequirement.PREFERRED}

    def setUp(self):
        self.user = User.objects.create_user(USERNAME, password=PASSWORD)
        self.device = Authenticator.objects.create(user=self.user, credential_id_data=CREDENTIAL_ID,
                                                   attestation_data=ATTESTATION_OBJECT)

    @override_settings(DJANGO_FIDO_TWO_STEP_AUTH=True)
    def test_no_user(self):
        with self.settings(LOGIN_URL='/login/'):
            response = self.client.get(self.url)

        self.assertRedirects(response, '/login/', fetch_redirect_response=False)

    @override_settings(DJANGO_FIDO_TWO_STEP_AUTH=False)
    def test_no_user_one_step(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    @override_settings(DJANGO_FIDO_TWO_STEP_AUTH=True)
    def test_get(self):
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = self.user.pk
        session.save()

        response = self.client.get(self.url)

        self.assertContains(response, 'Authenticate a FIDO 2 authenticator')

    @override_settings(DJANGO_FIDO_TWO_STEP_AUTH=True)
    def test_post(self):
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = self.user.pk
        session[FIDO2_REQUEST_SESSION_KEY] = self.state
        session.save()

        post = {'client_data': AUTHENTICATION_CLIENT_DATA, 'credential_id': CREDENTIAL_ID,
                'authenticator_data': AUTHENTICATOR_DATA, 'signature': SIGNATURE}
        with self.settings(LOGIN_REDIRECT_URL='/redirect/'):
            response = self.client.post(self.url, post)

        self.assertRedirects(response, '/redirect/', fetch_redirect_response=False)
        self.assertEqual(get_user(self.client), self.user)
        self.assertQuerysetEqual(Authenticator.objects.values_list('user', 'counter'), [(self.user.pk, 152)],
                                 transform=tuple)
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)
        self.assertNotIn(AUTHENTICATION_USER_SESSION_KEY, self.client.session)

    @override_settings(DJANGO_FIDO_TWO_STEP_AUTH=True)
    def test_post_no_session(self):
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = self.user.pk
        session.save()

        post = {'client_data': AUTHENTICATION_CLIENT_DATA, 'credential_id': CREDENTIAL_ID,
                'authenticator_data': AUTHENTICATOR_DATA, 'signature': SIGNATURE}
        response = self.client.post(self.url, post)

        self.assertContains(response, 'Authenticate a FIDO 2 authenticator')
        self.assertEqual(response.context['form'].errors, {NON_FIELD_ERRORS: ['Authentication request not found.']})
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)
        self.assertEqual(self.client.session[AUTHENTICATION_USER_SESSION_KEY], self.user.pk)

    @override_settings(DJANGO_FIDO_TWO_STEP_AUTH=True)
    def test_post_invalid_response(self):
        session = self.client.session
        session[AUTHENTICATION_USER_SESSION_KEY] = self.user.pk
        session[FIDO2_REQUEST_SESSION_KEY] = self.state
        session.save()

        post = {'client_data': AUTHENTICATION_CLIENT_DATA, 'credential_id': CREDENTIAL_ID,
                'authenticator_data': AUTHENTICATOR_DATA, 'signature': 'INVALID='}
        response = self.client.post(self.url, post)

        self.assertContains(response, 'Authenticate a FIDO 2 authenticator')
        self.assertEqual(response.context['form'].errors, {NON_FIELD_ERRORS: ['Authentication failed.']})
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)
        self.assertEqual(self.client.session[AUTHENTICATION_USER_SESSION_KEY], self.user.pk)

    @override_settings(
        DJANGO_FIDO_TWO_STEP_AUTH=False,
        AUTHENTICATION_BACKENDS=['django_fido.backends.Fido2GeneralAuthenticationBackend'],
        DJANGO_FIDO_AUTHENTICATION_BACKENDS=['django.contrib.auth.backends.ModelBackend'],
    )
    def test_post_one_step(self):
        session = self.client.session
        session[FIDO2_REQUEST_SESSION_KEY] = self.state
        session.save()

        post = {'username': USERNAME, 'password': PASSWORD, 'client_data': AUTHENTICATION_CLIENT_DATA,
                'credential_id': CREDENTIAL_ID, 'authenticator_data': AUTHENTICATOR_DATA, 'signature': SIGNATURE}
        with self.settings(LOGIN_REDIRECT_URL='/redirect/'):
            response = self.client.post(self.url, post)

        self.assertRedirects(response, '/redirect/', fetch_redirect_response=False)
        self.assertEqual(get_user(self.client), self.user)
        self.assertQuerysetEqual(Authenticator.objects.values_list('user', 'counter'), [(self.user.pk, 152)],
                                 transform=tuple)
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)
        self.assertNotIn(AUTHENTICATION_USER_SESSION_KEY, self.client.session)

    @override_settings(
        DJANGO_FIDO_TWO_STEP_AUTH=False,
        AUTHENTICATION_BACKENDS=['django_fido.backends.Fido2GeneralAuthenticationBackend'],
        DJANGO_FIDO_AUTHENTICATION_BACKENDS=['django.contrib.auth.backends.ModelBackend'],
    )
    def test_post_one_step_error(self):
        session = self.client.session
        session[FIDO2_REQUEST_SESSION_KEY] = self.state
        session.save()

        post = {'username': USERNAME, 'password': 'wrong_password', 'client_data': AUTHENTICATION_CLIENT_DATA,
                'credential_id': CREDENTIAL_ID, 'authenticator_data': AUTHENTICATOR_DATA, 'signature': SIGNATURE}
        response = self.client.post(self.url, post)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['form'].errors, {
            '__all__': ['Please enter a correct username and password and use valid FIDO2 security key.'],
        })
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)
        self.assertNotIn(AUTHENTICATION_USER_SESSION_KEY, self.client.session)

    @override_settings(
        DJANGO_FIDO_TWO_STEP_AUTH=False,
        AUTHENTICATION_BACKENDS=['django_fido.backends.Fido2GeneralAuthenticationBackend'],
        DJANGO_FIDO_AUTHENTICATION_BACKENDS=['django.contrib.auth.backends.ModelBackend'],
    )
    def test_post_one_step_no_request(self):
        post = {'username': USERNAME, 'password': PASSWORD, 'client_data': AUTHENTICATION_CLIENT_DATA,
                'credential_id': CREDENTIAL_ID, 'authenticator_data': AUTHENTICATOR_DATA, 'signature': SIGNATURE}
        response = self.client.post(self.url, post)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['form'].errors, {
            '__all__': ['Authentication request not found.'],
        })
        self.assertNotIn(FIDO2_REQUEST_SESSION_KEY, self.client.session)
        self.assertNotIn(AUTHENTICATION_USER_SESSION_KEY, self.client.session)
