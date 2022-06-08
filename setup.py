#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Setup script for django_fido."""
import os
from distutils.command.build import build

from setuptools import find_packages, setup
from setuptools.command.sdist import sdist

CLASSIFIERS = ['Development Status :: 4 - Beta',
               'License :: OSI Approved :: MIT License',
               'Framework :: Django',
               'Framework :: Django :: 3.0',
               'Framework :: Django :: 3.1',
               'Framework :: Django :: 3.2',
               'Framework :: Django :: 4.0',
               'Intended Audience :: Developers',
               'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
               'Operating System :: OS Independent',
               'Programming Language :: Python',
               'Programming Language :: Python :: 3',
               'Programming Language :: Python :: 3.7',
               'Programming Language :: Python :: 3.8',
               'Programming Language :: Python :: 3.9',
               'Programming Language :: Python :: 3.10',
               'Topic :: Internet :: WWW/HTTP',
               'Topic :: Security :: Cryptography',
               'Topic :: Software Development :: Libraries :: Python Modules']
INSTALL_REQUIRES = [
    'Django>=3.0',
    'fido2~=0.9',
    'sqlparse',  # sqlparse is required for Django < 2.2
    'django-app-settings>=0.7.1',
    'jwcrypto',
    'requests',
    'cryptography',
    'pyopenssl',
]
EXTRAS_REQUIRE = {'quality': ['isort', 'flake8', 'pydocstyle', 'mypy', 'polint'],
                  'test': ['mock', 'responses'],
                  'types': ['types-requests', 'types-mock', 'types-pyOpenSSL']}


def run_npm(build) -> bool:
    return not bool(os.environ.get('SKIP_NPM', False))


class custom_build(build):

    sub_commands = [
        ('compile_catalog', None),
        ('npm_install', run_npm),
        ('npm_run', run_npm),
    ] + build.sub_commands


class custom_sdist(sdist):

    def run(self):
        self.run_command('compile_catalog')
        # sdist is an old style class so super cannot be used.
        sdist.run(self)


setup(name='django-fido',
      description='Django application for FIDO protocol',
      author='Vlastimil Zíma',
      author_email='vlastimil.zima@nic.cz',
      url='https://github.com/CZ-NIC/django-fido',
      packages=find_packages(),
      include_package_data=True,
      python_requires='~=3.7',
      install_requires=INSTALL_REQUIRES,
      extras_require=EXTRAS_REQUIRE,
      keywords=['django', 'fido', 'u2f', 'fido2'],
      classifiers=CLASSIFIERS,
      cmdclass={'build': custom_build, 'sdist': custom_sdist})
