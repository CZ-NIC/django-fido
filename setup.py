#!/usr/bin/python
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
               'Intended Audience :: Developers',
               'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
               'Operating System :: OS Independent',
               'Programming Language :: Python',
               'Programming Language :: Python :: 2',
               'Programming Language :: Python :: 2.7',
               'Programming Language :: Python :: 3',
               'Programming Language :: Python :: 3.5',
               'Programming Language :: Python :: 3.6',
               'Topic :: Internet :: WWW/HTTP',
               'Topic :: Security :: Cryptography',
               'Topic :: Software Development :: Libraries :: Python Modules']
INSTALL_REQUIRES = ['Django>=1.11', 'python-u2flib-server>=5', 'six']
EXTRAS_REQUIRE = {'quality': ['isort', 'flake8', 'pydocstyle', 'polint'],
                  'test': ['mock']}


class custom_build(build):

    sub_commands = [('compile_catalog', lambda x: True)] + build.sub_commands


class custom_sdist(sdist):

    def run(self):
        self.run_command('compile_catalog')
        # sdist is an old style class so super cannot be used.
        sdist.run(self)


setup(name='django-fido',
      version=django_fido.__version__,
      description='Django application for FIDO protocol U2F',
      long_description=LONG_DESCRIPTION,
      long_description_content_type='text/markdown',
      author='Vlastimil Zíma',
      author_email='vlastimil.zima@gmail.com',
      url='https://github.com/ziima/django-fido',
      packages=find_packages(),
      include_package_data=True,
      python_requires='>=2.7',
      setup_requires=['Babel >=2.3'],
      install_requires=INSTALL_REQUIRES,
      extras_require=EXTRAS_REQUIRE,
      keywords=['django', 'fido', 'u2f'],
      classifiers=CLASSIFIERS,
      cmdclass={'build': custom_build, 'sdist': custom_sdist})
