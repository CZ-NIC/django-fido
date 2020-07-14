from unittest import skipIf
from unittest.mock import patch

from django import VERSION as DJANGO_VERSION
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse, reverse_lazy

import django_fido.admin.authenticator
from django_fido.models import Authenticator

from .data import ATTESTATION_OBJECT, REGISTRATION_CLIENT_DATA, USER_FIRST_NAME, USER_LAST_NAME, USERNAME

User = get_user_model()


@override_settings(ROOT_URLCONF='django_fido.tests.urls')
class TestFido2RegistrationRequestAdminView(TestCase):

    url = reverse_lazy('admin:django_fido_registration_request')

    def setUp(self):
        self.user = User.objects.create_user(
            USERNAME, first_name=USER_FIRST_NAME, last_name=USER_LAST_NAME,
            is_staff=True,
        )
        self.superuser = User.objects.create_superuser(
            'admin',
            first_name='Artem', last_name='Aardvark',
            email='admin@example.com', password='passwd',
        )

    def test_anonymous(self):
        response = self.client.get(self.url)
        self.assertRedirects(response, '/admin/login/?next={}'.format(self.url), fetch_redirect_response=False)

    @skipIf(DJANGO_VERSION < (2, 1), "Skip for old Django versions.")
    def test_permission_denied(self):
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_get(self):
        self.client.force_login(self.superuser)

        response = self.client.get(self.url, data={'user': str(self.user.pk)})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['publicKey']['user'], {
            'displayName': 'Kryten 2X4B-523P',
            'id': 'kryten',
            'name': 'kryten',
        })

    def test_get_user_not_exist(self):
        self.client.force_login(self.superuser)
        response = self.client.get(self.url, data={'user': '42'})
        self.assertEqual(response.status_code, 404)


@override_settings(ROOT_URLCONF='django_fido.tests.urls')
class TestAuthenticatorAddView(TestCase):

    url = reverse_lazy('admin:django_fido_authenticator_add')

    def setUp(self):
        self.user = User.objects.create_user(
            USERNAME, first_name=USER_FIRST_NAME, last_name=USER_LAST_NAME,
            is_staff=True,
        )
        self.superuser = User.objects.create_superuser(
            'admin',
            first_name='Artem', last_name='Aardvark',
            email='admin@example.com', password='passwd',
        )

    @skipIf(DJANGO_VERSION < (2, 1), "Skip for old Django versions.")
    def test_permission_denied(self):
        self.client.force_login(self.user)

        response_get = self.client.get(self.url)
        response_post = self.client.post(self.url)

        self.assertEqual(response_get.status_code, 403)
        self.assertEqual(response_post.status_code, 403)

    @patch.object(django_fido.admin.authenticator.AuthenticatorAddView, 'complete_registration', return_value=None)
    def test_post(self, mock):
        self.client.force_login(self.superuser)

        response = self.client.post(self.url, data={
            'user': self.user.pk,
            'client_data': REGISTRATION_CLIENT_DATA,
            'attestation': ATTESTATION_OBJECT,
            'label': 'My key',
        })

        self.assertRedirects(response, reverse('admin:django_fido_authenticator_change', args=(1,)))
        self.assertQuerysetEqual(
            Authenticator.objects.values_list('pk', 'user__username', 'attestation_data', 'label'),
            [(1, 'kryten', ATTESTATION_OBJECT, 'My key')],
            transform=tuple,
        )
