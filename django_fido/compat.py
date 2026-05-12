"""Fido2 library version compatibility."""

from importlib.metadata import version as _pkg_version

FIDO2_2 = int(_pkg_version("fido2").split(".")[0]) >= 2
