"""Command to download metadata for authenticators."""
from __future__ import unicode_literals

import json
from base64 import urlsafe_b64decode
from typing import Any, Dict

import requests
from django.core.management.base import BaseCommand, CommandError
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

from django_fido.constants import PEM_CERT_TEMPLATE
from django_fido.models import AuthenticatorMetadata
from django_fido.settings import SETTINGS


class Command(BaseCommand):
    """Download metadata for authenticators."""

    help = "Download metadata for authenticators."""

    def add_arguments(self, parser):
        """Parse command arguments."""

    def _get_metadata(self) -> Dict[str, Any]:
        """Download the metadata TOC."""
        metadata = requests.get(SETTINGS.metadata_service['url'],
                                params={'token': SETTINGS.metadata_service['access_token']},
                                timeout=SETTINGS.metadata_service['timeout'])
        # First, we decode the unverified headers to get the certificate
        decoded_jwt = JWT(jwt=metadata.content.decode())
        # x5c element in header contains the signing certificate and possibly intermediate certificates
        # Use the first one to verify signature, the others can be used to verify the first one
        decoding_key = JWK.from_pem(PEM_CERT_TEMPLATE.format(decoded_jwt.token.jose_header['x5c'][0]).encode())
        decoded_jwt.deserialize(metadata.content.decode(), key=decoding_key)

        return json.loads(decoded_jwt.claims)

    def handle(self, **options):
        """Donwload and parse metadata from metadata service."""
        if SETTINGS.metadata_service is None:
            raise CommandError('access_token setting must be specified for this command to work.')

        metadata = self._get_metadata()
        for authenticator_data in metadata['entries']:
            if 'aaid' in authenticator_data:
                identification = authenticator_data['aaid']
            elif 'aaguid' in authenticator_data:
                identification = authenticator_data['aaguid']
            elif 'attestationCertificateKeyIdentifiers' in authenticator_data:
                identification = authenticator_data['attestationCertificateKeyIdentifiers']
            else:
                self.stderr.write('Cannot determine the identificator from metadata response.')
                continue
            url = authenticator_data['url']
            authenticator, _ = AuthenticatorMetadata.objects.get_or_create(identifier=identification)
            authenticator.metadata_entry = json.dumps(authenticator_data)
            auth_metadata = requests.get(url, params={'token': SETTINGS.metadata_service['access_token']},
                                         timeout=SETTINGS.metadata_service['timeout'])
            authenticator.detailed_metadata_entry = urlsafe_b64decode(auth_metadata.content)
            authenticator.save()
