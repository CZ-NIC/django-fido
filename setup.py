#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Setup script for django_fido."""
from __future__ import unicode_literals

from distutils.command.build import build

from setuptools import find_packages, setup
from setuptools.command.sdist import sdist

import django_fido

LONG_DESCRIPTION = open('README.md').read() + '\n\n' + open('CHANGELOG.md').read()
CLASSIFIERS = ['Development Status :: 4 - Beta',
               'License :: OSI Approved :: MIT License',
               'Framework :: Django',
               'Framework :: Django :: 1.11',
               'Framework :: Django :: 2.0',
               'Framework :: Django :: 2.1',
               'Framework :: Django :: 2.2',
               'Intended Audience :: Developers',
               'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
               'Operating System :: OS Independent',
               'Programming Language :: Python',
               'Programming Language :: Python :: 3',
               'Programming Language :: Python :: 3.5',
               'Programming Language :: Python :: 3.6',
               'Programming Language :: Python :: 3.7',
               'Topic :: Internet :: WWW/HTTP',
               'Topic :: Security :: Cryptography',
               'Topic :: Software Development :: Libraries :: Python Modules']
INSTALL_REQUIRES = ['Django>=1.11', 'fido2', 'sqlparse']  # sqlparse is required for Django < 2.2
EXTRAS_REQUIRE = {'quality': ['isort', 'flake8', 'pydocstyle', 'mypy', 'polint'],
                  'test': ['mock']}


class custom_build(build):

    sub_commands = [('compile_catalog', None), ('build_js', None)] + build.sub_commands


class custom_sdist(sdist):

    def run(self):
        self.run_command('compile_catalog')
        # sdist is an old style class so super cannot be used.
        sdist.run(self)


setup(name='django-fido',
      version=django_fido.__version__,
      description='Django application for FIDO protocol',
      long_description=LONG_DESCRIPTION,
      long_description_content_type='text/markdown',
      author='Vlastimil Zíma',
      author_email='vlastimil.zima@nic.cz',
      url='https://github.com/CZ-NIC/django-fido',
      packages=find_packages(),
      include_package_data=True,
      python_requires='~=3.5',
      setup_requires=['Babel >=2.3', 'setuptools_webpack'],
      install_requires=INSTALL_REQUIRES,
      extras_require=EXTRAS_REQUIRE,
      keywords=['django', 'fido', 'u2f', 'fido2'],
      classifiers=CLASSIFIERS,
      webpack_output_path='django_fido/static/django_fido',
      cmdclass={'build': custom_build, 'sdist': custom_sdist})
