"""Utilities for django_fido."""
from typing import Any, Callable, Union

from django.utils.module_loading import import_string


def process_callable(item: Union[Callable, str, None], *args: Any, **kwargs: Any) -> Any:
    """Call supplied callable or dotted path source.

    @raise ImportError: If supplied item[str] is not an importable dotted path.
    """

    if not item:
        return

    if isinstance(item, str):
        return import_string(item)(*args, **kwargs)

    if callable(item):
        return item(*args, **kwargs)
