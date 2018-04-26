"""
Django FIDO constants.

Session keys to store U2F requests:
 * REGISTRATION_REQUEST_SESSION_KEY

U2F request type identifiers:
 * U2F_REGISTRATION_REQUEST
These are shared between code and JS.
"""
from __future__ import unicode_literals

REGISTRATION_REQUEST_SESSION_KEY = 'fido_u2f_registration_request'

U2F_REGISTRATION_REQUEST = 'registration'
