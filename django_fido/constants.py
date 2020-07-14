"""
Django FIDO constants.

Session key to store FIDO2 requests: FIDO2_REQUEST_SESSION_KEY

Session key to store user PK for django fido authentication
 * AUTHENTICATION_USER_SESSION_KEY

FIDO 2 request type identifiers:
 * FIDO2_REGISTRATION_REQUEST
 * FIDO2_AUTHENTICATION_REQUEST
These are shared between code and JS.
"""
from enum import Enum, unique

FIDO2_REQUEST_SESSION_KEY = 'fido2_request'

AUTHENTICATION_USER_SESSION_KEY = 'django_fido_user'

FIDO2_REGISTRATION_REQUEST = 'registration'
FIDO2_AUTHENTICATION_REQUEST = 'authentication'

PEM_CERT_TEMPLATE = '-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n'
NULL_AAGUID = b'\x00' * 16

# According to RFC 7518
HASH_ALG_MAPPING = {
    'HS256': 'SHA256',
    'HS384': 'SHA384',
    'HS512': 'SHA512',
    'ES256': 'SHA256',
    'ES384': 'SHA384',
    'ES512': 'SHA512',
    'RS256': 'SHA256',
    'RS384': 'SHA384',
    'RS512': 'SHA512',
}


@unique
class AuthLevel(str, Enum):
    """Enum for Levels of certification."""

    NONE = 'NOT_FIDO_CERTIFIED'
    SELF = 'SELF_ASSERTION_SUBMITTED'
    L0 = 'FIDO_CERTIFIED'
    L1 = 'FIDO_CERTIFIED_L1'
    L2 = 'FIDO_CERTIFIED_L2'
    L3 = 'FIDO_CERTIFIED_L3'
    L4 = 'FIDO_CERTIFIED_L4'
    L5 = 'FIDO_CERTIFIED_L5'


@unique
class AuthVulnerability(str, Enum):
    """Enum for Authenticator vulnerabilities."""

    REVOKED = 'REVOKED'
    USER_BYPASS = 'USER_VERIFICATION_BYPASS'
    ATTESTATION_COMPROMISE = 'ATTESTATION_KEY_COMPROMISE'
    REMOTE_COMPROMISE = 'USER_KEY_REMOTE_COMPROMISE'
    PHYSICAL_COMPROMISE = 'USER_KEY_PHYSICAL_COMPROMISE'
