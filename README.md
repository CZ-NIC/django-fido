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

## Changes ##
See [changelog](https://github.com/CZ-NIC/django-fido/blob/master/CHANGELOG.md).

## Testing ##
Use `tox` to run tests

    tox

## License ##

See [LICENSE](https://github.com/CZ-NIC/django-fido/blob/master/LICENSE).
