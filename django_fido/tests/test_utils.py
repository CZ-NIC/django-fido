"""Tests for utils module."""
from django.contrib.auth import get_user_model
from django.test import TestCase

from django_fido.utils import process_callable

from .data import USER_FIRST_NAME, USER_LAST_NAME, USERNAME
from .utils import helper_str

User = get_user_model()


class ProcessCallableTest(TestCase):
    """Tests for process_callable."""

    def setUp(self):
        self.user = User.objects.create_user(USERNAME, first_name=USER_FIRST_NAME, last_name=USER_LAST_NAME)

    def test_call_path(self):
        self.assertEqual(process_callable("django_fido.tests.utils.helper_str", self.user), USER_LAST_NAME)

    def test_call_callable(self):
        self.assertEqual(process_callable(helper_str, self.user), USER_LAST_NAME)

    def test_no_item(self):
        self.assertEqual(process_callable(None, self.user), None)
