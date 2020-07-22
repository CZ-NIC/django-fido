"""Command to download metadata for authenticators."""
import base64
import hashlib
import json
from typing import Any, Dict, Tuple

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from django.core.management.base import BaseCommand, CommandError
from jwcrypto.jwk import JWK
from jwcrypto.jws import InvalidJWSSignature
from jwcrypto.jwt import JWT
from OpenSSL import crypto

from django_fido.constants import HASH_ALG_MAPPING, PEM_CERT_TEMPLATE
from django_fido.models import AuthenticatorMetadata
from django_fido.settings import SETTINGS


class InvalidCert(Exception):
    """Raised when certificate validation fails."""


def urlsafe_b64decode(decodable: bytes) -> bytes:
    """Alternative implementation to fill the necessary padding."""
    m = len(decodable) % 4
    if m == 2:
        decodable += b'=='
    elif m == 3:
        decodable += b'='
    return base64.urlsafe_b64decode(decodable)


def _prepare_crypto_store(jwt: JWT) -> crypto.X509Store:
    """Prepare crytpographic store for verification."""
    # Create crypto context
    store = crypto.X509Store()
    for key in jwt.token.jose_header['x5c'][1:]:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, PEM_CERT_TEMPLATE.format(key).encode())
        store.add_cert(cert)
    for root_cert_file in SETTINGS.metadata_service['certificate']:
        with open(str(root_cert_file)) as root_file:
            root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, root_file.read())
    store.add_cert(root_cert)
    # CRL handling
    # FIXME: This part is not tested in unittests (intentionally) as it might be more suited for integration testing
    for crl_file in SETTINGS.metadata_service['crl_list']:
        with open(str(crl_file), 'rb') as file:
            crl_list = x509.load_pem_x509_crl(file.read(), default_backend())
        store.add_crl(crypto.CRL.from_cryptography(crl_list))
    if SETTINGS.metadata_service['crl_list']:
        store.set_flags(crypto.X509StoreFlags.CRL_CHECK)
    return store


def verify_certificate(jwt: JWT) -> JWK:
    """Get (and verify) the signing key from JWT."""
    # First element in the header is our actual key
    try:
        decoding_key = JWK.from_pem(PEM_CERT_TEMPLATE.format(jwt.token.jose_header['x5c'][0]).encode())
    except ValueError:
        raise InvalidCert('Cannot decode key.')
    if SETTINGS.metadata_service['disable_cert_verification']:
        return decoding_key
    if not SETTINGS.metadata_service['certificate']:
        raise CommandError("Certificate verification enabled, but no certificate set. "
                           "Please set certificate or disable validation.")
    # Create context and verify
    store = _prepare_crypto_store(jwt)
    decoding_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                            PEM_CERT_TEMPLATE.format(jwt.token.jose_header['x5c'][0]).encode())
    store_ctx = crypto.X509StoreContext(store, decoding_cert)
    try:
        store_ctx.verify_certificate()
    except crypto.X509StoreContextError:
        raise InvalidCert('Key could not be verified.')
    else:
        return decoding_key


def _get_metadata() -> Tuple[Dict[str, Any], str]:
    """Download the metadata TOC."""
    try:
        metadata = requests.get(SETTINGS.metadata_service['url'],
                                params={'token': SETTINGS.metadata_service['access_token']},
                                timeout=SETTINGS.metadata_service['timeout'])
    except requests.exceptions.RequestException:
        raise CommandError('MDS response error.')
    # First, we decode the unverified headers to get the certificate
    try:
        decoded_jwt = JWT(jwt=metadata.content.decode())
    except ValueError:
        raise CommandError('MDS response malformed.')
    # x5c element in header contains the signing certificate and possibly intermediate certificates
    # Use the first one to verify signature, the others can be used to verify the first one
    try:
        decoding_key = verify_certificate(decoded_jwt)
    except InvalidCert:
        raise CommandError('Could not read the key.')
    try:
        decoded_jwt.deserialize(metadata.content.decode(), key=decoding_key)
    except InvalidJWSSignature:
        raise CommandError('Could not verify MDS signature.')
    # Return parsed metadata and the algorith for signing
    return json.loads(decoded_jwt.claims), json.loads(decoded_jwt.header)['alg']


class Command(BaseCommand):
    """Download metadata for authenticators."""

    help = "Download metadata for authenticators."""

    def add_arguments(self, parser):
        """Parse command arguments."""

    def handle(self, **options):
        """Donwload and parse metadata from metadata service."""
        try:
            SETTINGS.metadata_service
        except TypeError:
            raise CommandError('access_token setting must be specified for this command to work.')

        metadata, alg = _get_metadata()
        # Convert alg name to corresponding hashing algorithm
        hash_alg = HASH_ALG_MAPPING.get(alg)
        if hash_alg is None or hash_alg.lower() not in hashlib.algorithms_available:
            raise CommandError('Unsupported hash algorithm {}.'.format(alg))
        for authenticator_data in metadata['entries']:
            if 'aaid' in authenticator_data:
                identifier = authenticator_data['aaid']
            elif 'aaguid' in authenticator_data:
                identifier = authenticator_data['aaguid']
            elif 'attestationCertificateKeyIdentifiers' in authenticator_data:
                identifier = authenticator_data['attestationCertificateKeyIdentifiers']
            else:
                self.stderr.write('Cannot determine the identificator from metadata response.')
                continue
            url = authenticator_data['url']
            authenticator, _ = AuthenticatorMetadata.objects.get_or_create(url=url)
            authenticator.identifier = identifier
            authenticator.metadata_entry = json.dumps(authenticator_data)
            auth_metadata = requests.get(url, params={'token': SETTINGS.metadata_service['access_token']},
                                         timeout=SETTINGS.metadata_service['timeout'])
            hash = hashlib.new(hash_alg, auth_metadata.content)
            if hash.digest() != urlsafe_b64decode(authenticator_data['hash'].encode()):
                self.stderr.write('Hash invalid for authenticator {}.'.format(identifier))
            else:
                authenticator.detailed_metadata_entry = urlsafe_b64decode(auth_metadata.content).decode()
            authenticator.save()
