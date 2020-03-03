# Changelog #

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
