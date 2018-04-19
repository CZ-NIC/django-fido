"""Settings for tests."""
from __future__ import unicode_literals

SECRET_KEY = 'Gazpacho!'

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.auth',
    'django_fido',
]

DATABASES = {
        'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}
}

MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
]
