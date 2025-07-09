#!/usr/bin/python3
"""Setup script for django_fido."""

import os
from distutils.command.build import build

from setuptools import setup
from setuptools.command.sdist import sdist


def run_npm(build) -> bool:
    return not bool(os.environ.get("SKIP_NPM", False))


class custom_build(build):
    sub_commands = [
        ("compile_catalog", None),
        ("npm_install", run_npm),
        ("npm_run", run_npm),
    ] + build.sub_commands


class custom_sdist(sdist):
    def run(self):
        self.run_command("compile_catalog")
        # sdist is an old style class so super cannot be used.
        sdist.run(self)


setup(
    cmdclass={"build": custom_build, "sdist": custom_sdist},
)
