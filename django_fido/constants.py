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
from __future__ import unicode_literals

from enum import Enum, unique

FIDO2_REQUEST_SESSION_KEY = 'fido2_request'

AUTHENTICATION_USER_SESSION_KEY = 'django_fido_user'

FIDO2_REGISTRATION_REQUEST = 'registration'
FIDO2_AUTHENTICATION_REQUEST = 'authentication'

PEM_CERT_TEMPLATE = '-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n'


@unique
class AuthLevel(str, Enum):
    """Enum for Levels of certification."""

    NONE = 'NOT_FIDO_CERTIFIED'
    L0 = 'FIDO_CERTIFIED'
    L1 = 'FIDO_CERTIFIED_L1'
    L2 = 'FIDO_CERTIFIED_L2'
    L3 = 'FIDO_CERTIFIED_L3'
    L4 = 'FIDO_CERTIFIED_L4'
    L5 = 'FIDO_CERTIFIED_L5'
