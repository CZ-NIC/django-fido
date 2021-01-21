# Changelog #

## Unreleased ##

## 0.30 ##
 * Counter is now stored as BigInteger.
 * Restrict version of `fido2` library to `<0.9.0`.

## 0.29 ##
 * Catch `InvalidAttestation` error in registration view.

## 0.28 ##
 * Updated error strings to be more informative.

## 0.27 ##
 * Throw form error on unknown attestation format instead of a server error.

## 0.26 ##
 * Improve metadata matching for U2F authenticators.

## 0.25 ##
 * **BREAKING** - AuthenticatorMetadata are now looked up by URL and not by an identifier. If you are downloading metadata, you need to clear them all and re-download to prevent multiple objects for each authenticator.
 * Update JS dependencies

## 0.24 ##
 * Metadata validation

## 0.23 ##
 * Display no authenticator error
 * `error` key in repsponse of `BaseFido2RequestView` is now deprecated and will be removed in the future
 * Added metadata download and reporting

## 0.22 ##
 * Use username as a backup `displayName`

## 0.21 ##
 * Create FIDO errors list when needed unless it already exists
 * Clear FIDO errors list before each registration or authentication request

## 0.20 ##
 * Fix Django 3.0 compatibility issues in templates

## 0.19 ##
 * Added class attribute `attestation_types` to `Fido2ViewMixin` to specify allowed attestation types during registration.
 * Set default value of setting `DJANGO_FIDO_AUTHENTICATION_BACKENDS` to list containing `django.contrib.auth.backends.ModelBackend`

## 0.18 ##
 * Fix issue caused by default value of `DJANGO_FIDO_AUTHENTICATION_BACKENDS`. It is now empty list.

## 0.17 ##
 * **BREAKING** Replace `Fido2ModelAuthenticationBackend` with more general `Fido2GeneralAuthenticationBackend`.

## 0.16 ##
 * **BREAKING** Authenticator `label` has to be unique for user. This can potentialy break if you have multiple tokens for user.
 * Add authenticator admin.
 * Add one step authentication.

## 0.15 ##
 * Add ``DJANGO_FIDO_RP_NAME`` setting.
 * Add back autosubmit on login view.
 * Display error in login view on server request error.

## 0.14 ##
 * Add label to Authenticator model.
 * Remove autosubmit on registration view.
 * Update JS dependencies.

## 0.13 ##
 * Support fido2 0.6-0.8.
 * Add support for python 3.8.
 * Fixup annotations.

## 0.12 ##
 * Fix dependencies (add webpack-cli).

## 0.11 ##
 * Fix webpack output path.

## 0.10 ##
 * Fix dependencies (add webpack).

## 0.9 ##
 * Refactor JS code.
 * Update setup.
 * Add bumpversion.

## 0.8 ##
 * Fix JS translation lazynes.
 * For empty values, submit button reload page.

## 0.7 ##
 * Add credential ID field.
 * Drop `credential_data` field.
 * Update error messages.
 * Mark django-fido as typed.
 * Add JS hooks.

## 0.6 ##
 * Use FIDO 2 instead of U2F.
 * Drop python 2.7.
 * Add annotations and mypy check.
 * Move repository to a CZ.NIC account.

## 0.5 ##
 * Fix JS translation lazynes

## 0.4 ##
 * Update JS messages.
 * Drop unused `polint` environment in tox.

## 0.3 ##
 * Store attestation certificate in database #6
 * Install package data #7

## 0.2 ##
 * Accept any arguments in `BaseU2fRequestView.get`
 * Add czech translations
 * Fix links in README

## 0.1 ##
 * Initial version
