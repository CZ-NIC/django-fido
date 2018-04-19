"""
Django FIDO constants.

Session keys to store U2F requests:
 * REGISTRATION_REQUEST_SESSION_KEY
"""
from __future__ import unicode_literals

REGISTRATION_REQUEST_SESSION_KEY = 'fido_u2f_registration_request'
