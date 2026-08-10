"""Fido2 library version compatibility."""

from importlib.metadata import version as _pkg_version

FIDO2_2 = int(_pkg_version("fido2").split(".")[0]) >= 2
FIDO2_22 = tuple(map(int, _pkg_version("fido2").split("."))) >= (2, 2, 0)
