"""Test utilities."""
from typing import TYPE_CHECKING

if TYPE_CHECKING: # pragma: no branch
    from django.contrib.auth import get_user_model

    User = get_user_model()

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.static',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

def helper_str(user: "User"):
    return user.last_name

def helper_bytes(user: "User"):
    return bytes(user.last_name, "utf-8")
