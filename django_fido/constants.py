"""
Django FIDO constants.

Session keys to store U2F requests:
 * REGISTRATION_REQUEST_SESSION_KEY
 * AUTHENTICATION_REQUEST_SESSION_KEY

Session key to store user PK for U2F authentication
 * AUTHENTICATION_USER_SESSION_KEY

U2F request type identifiers:
 * U2F_REGISTRATION_REQUEST
 * U2F_AUTHENTICATION_REQUEST
These are shared between code and JS.
"""
from __future__ import unicode_literals

REGISTRATION_REQUEST_SESSION_KEY = 'fido_u2f_registration_request'
AUTHENTICATION_REQUEST_SESSION_KEY = 'fido_u2f_authentication_request'

AUTHENTICATION_USER_SESSION_KEY = 'fido_u2f_user'

U2F_REGISTRATION_REQUEST = 'registration'
U2F_AUTHENTICATION_REQUEST = 'authentication'
