# django-fido #

[![Python tests](https://github.com/CZ-NIC/django-fido/actions/workflows/python-test.yml/badge.svg)](https://github.com/CZ-NIC/django-fido/actions/workflows/python-test.yml)
[![JS tests](https://github.com/CZ-NIC/django-fido/actions/workflows/js-test.yml/badge.svg)](https://github.com/CZ-NIC/django-fido/actions/workflows/js-test.yml)
[![codecov](https://codecov.io/gh/CZ-NIC/django-fido/branch/master/graph/badge.svg)](https://codecov.io/gh/CZ-NIC/django-fido)

> Django application for FIDO protocol

Django-fido provides basic components for FIDO 2 authentication - model to store user's FIDO 2 authenticator data and basic views.

## Table of Contents ##
- [Dependencies](#dependencies)
- [Configuration](#configuration)
- [Changes](#changes)
- [Testing](#testing)
- [License](#license)

## Dependencies ##
 * Python 3.5 and higher
 * Django >= 3.0

## Configuration ##

1. Add `django_fido` to `INSTALLED_APPS`.
2. Add `django_fido.backends.Fido2AuthenticationBackend` to `AUTHENTICATION_BACKENDS`.
3. Link django-fido URLs into your `urls.py`:

       urlpatterns += [
          url(r'', include('django_fido.urls')),
       ]

4. If you wish, set string variable `DJANGO_FIDO_RP_NAME`.

### Extra configuration ###
#### DJANGO_FIDO_RESIDENT_KEY ####
Default: False

Purpose: Set to True to enable discoverable credentials, private key and associated metadata is stored in persistent memory on the authenticator. This is useful for passwordless authentication.

## One step authentication

You can also decide to use one step authentication.
In this case, you will use just one authentication form, that will collect username, password and FIDO2 credentials.
In addition to the configuration above, you also need to:

1. Set `DJANGO_FIDO_TWO_STEP_AUTH` to `False`.
2. Replace `django_fido.backends.Fido2AuthenticationBackend` with
   `django_fido.backends.Fido2GeneralAuthenticationBackend` in `AUTHENTICATION_BACKENDS`.
3. Set `DJANGO_FIDO_AUTHENTICATION_BACKENDS` to the list of your additional authentication backends, if you use others
   than `django.contrib.auth.backends.ModelBackend`.
4. Set `data-autosubmit-off` attribute on the form element of your login page.

Please note that your login form must have a field named `username`, even if your `USERNAME_FIELD` is not `username`.

## Metadata download

If you want to be able to download authenticator metadata, you need to set `DJANGO_FIDO_METADATA_SERVICE` setting which is a dictionary.
The MDS is available in two versions v2 (deprecated) and v3 (current).
If you want to use MDSv2, you have to set a valid `ACCESS_TOKEN`.
If you want to use MDSv3, you have to set `MDS_FORMAT` to `3` and set a valid `URL` providing the MDSv3 data.
Then you can periodically run the `download_authenticator_metadata` management command.
If metadata are available for the given `Authenticator`, its `metadata` property will be an object.
The `level`, `vulnerabilities` and `is_update_available` methods on `metadata` can be used to determine the trust and certification level.

## Passwordless

This authentication requires "discoverable credential" and using that credential to perform a user lookup using the passwordless authentication backend

1. Set `DJANGO_FIDO_RESIDENT_KEY` to `True`
2. Set 'DJANGO_FIDO_PASSWORDLESS_AUTH' to 'True'
3. Set 'DJANGO_FIDO_TWO_STEP_AUTH' to 'False'
3. Replace `django_fido.backends.Fido2AuthenticationBackend` with
   `django_fido.backends.Fido2PasswordlessAuthenticationBackend` in `AUTHENTICATION_BACKENDS`.

## Changes ##
See [changelog](https://github.com/CZ-NIC/django-fido/blob/master/CHANGELOG.md).

## Testing ##
Use `tox` to run tests

    tox

## License ##

See [LICENSE](https://github.com/CZ-NIC/django-fido/blob/master/LICENSE).
