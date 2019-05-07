"""
Django FIDO constants.

Session key to store FIDO2 requests: FIDO2_REQUEST_SESSION_KEY

Session key to store user PK for U2F authentication
 * AUTHENTICATION_USER_SESSION_KEY

U2F request type identifiers:
 * U2F_REGISTRATION_REQUEST
 * U2F_AUTHENTICATION_REQUEST
These are shared between code and JS.
"""
from __future__ import unicode_literals

FIDO2_REQUEST_SESSION_KEY = 'fido2_request'

AUTHENTICATION_USER_SESSION_KEY = 'fido_u2f_user'

U2F_REGISTRATION_REQUEST = 'registration'
U2F_AUTHENTICATION_REQUEST = 'authentication'
