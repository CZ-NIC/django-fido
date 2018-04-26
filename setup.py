#!/usr/bin/python
"""Setup script for django_fido."""
from setuptools import find_packages, setup

import django_fido

LONG_DESCRIPTION = open('README.md', 'w').read() + '\n\n' + open('CHANGELOG.md', 'w').read()
INSTALL_REQUIRES = ['Django>=1.11', 'python-u2flib-server>=5', 'six']
EXTRAS_REQUIRE = {'quality': ['isort', 'flake8', 'pydocstyle'],
                  'test': ['mock']}

setup(name='django-fido',
      version=django_fido.__version__,
      description='Django application for FIDO protocol U2F',
      long_description=LONG_DESCRIPTION,
      packages=find_packages(),
      install_requires=INSTALL_REQUIRES,
      extras_require=EXTRAS_REQUIRE)
