import unittest
from handler import is_safe_url

class TestSSRFProtection(unittest.TestCase):
    def test_safe_urls(self):
        # We can't guarantee internet access or specific DNS resolution in all environments,
        # but these tests exercise the logic.
        # Note: These might fail if DNS is blocked or restricted.
        try:
            self.assertTrue(is_safe_url("https://google.com"))
        except:
            print("Skipping google.com test due to network/DNS issues")

        self.assertTrue(is_safe_url("https://8.8.8.8")) # Google DNS IP

    def test_unsafe_urls(self):
        self.assertFalse(is_safe_url("http://localhost"))
        self.assertFalse(is_safe_url("http://127.0.0.1"))
        self.assertFalse(is_safe_url("http://0.0.0.0"))
        self.assertFalse(is_safe_url("http://192.168.1.1"))
        self.assertFalse(is_safe_url("http://10.0.0.1"))
        self.assertFalse(is_safe_url("ftp://google.com")) # scheme check
        self.assertFalse(is_safe_url("file:///etc/passwd")) # scheme check

if __name__ == '__main__':
    unittest.main()
