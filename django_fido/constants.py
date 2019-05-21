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

FIDO2_REQUEST_SESSION_KEY = 'fido2_request'

AUTHENTICATION_USER_SESSION_KEY = 'django_fido_user'

FIDO2_REGISTRATION_REQUEST = 'registration'
FIDO2_AUTHENTICATION_REQUEST = 'authentication'
