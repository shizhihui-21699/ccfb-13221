"""Tests for the target authorization guard (no network for private IPs)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smuggler.authorize import assert_authorized, is_private_target


class TestAuthorization(unittest.TestCase):
    def test_loopback_allowed_without_confirmation(self):
        # Must not raise.
        assert_authorized("http://127.0.0.1:8080/", acknowledged=False)
        assert_authorized("http://localhost:8080/", acknowledged=False)

    def test_ipv6_loopback_does_not_crash(self):
        # Regression: is_unique_local does not exist on IPv6Address.
        self.assertTrue(is_private_target("::1"))

    def test_public_target_refused_without_acknowledgement(self):
        with self.assertRaises(PermissionError):
            assert_authorized("http://8.8.8.8/", acknowledged=False)

    def test_public_target_ack_without_env_still_refused(self):
        with self.assertRaises(PermissionError):
            assert_authorized("http://8.8.8.8/", acknowledged=True)

    def test_public_target_passes_with_ack_and_env(self):
        os.environ["SMUGGLER_CONFIRM"] = "YES_I_HAVE_AUTHORIZATION"
        try:
            assert_authorized("http://8.8.8.8/", acknowledged=True)
        finally:
            del os.environ["SMUGGLER_CONFIRM"]


if __name__ == "__main__":
    unittest.main()
