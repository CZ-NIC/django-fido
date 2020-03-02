# django-fido #

[![Build Status](https://travis-ci.org/CZ-NIC/django-fido.svg?branch=master)](https://travis-ci.org/CZ-NIC/django-fido)
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
 * Django >= 1.11

## Configuration ##

1. Add `django_fido` to `INSTALLED_APPS`.
2. Add `django_fido.backends.Fido2AuthenticationBackend` to `AUTHENTICATION_BACKENDS`.
3. Link django-fido URLs into your `urls.py`:

       urlpatterns += [
          url(r'', include('django_fido.urls')),
       ]

4. If you wish, set string variable `DJANGO_FIDO_RP_NAME`.

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

## Changes ##
See [changelog](https://github.com/CZ-NIC/django-fido/blob/master/CHANGELOG.md).

## Testing ##
Use `tox` to run tests

    tox

## License ##

See [LICENSE](https://github.com/CZ-NIC/django-fido/blob/master/LICENSE).
