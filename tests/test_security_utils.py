import unittest
from security_utils import is_safe_url

class TestIsSafeUrl(unittest.TestCase):
    def test_safe_urls(self):
        self.assertTrue(is_safe_url("https://google.com"))
        self.assertTrue(is_safe_url("http://example.com/foo"))
        self.assertTrue(is_safe_url("https://8.8.8.8"))

    def test_unsafe_schemes(self):
        self.assertFalse(is_safe_url("ftp://example.com"))
        self.assertFalse(is_safe_url("file:///etc/passwd"))
        self.assertFalse(is_safe_url("javascript:alert(1)"))

    def test_private_ips(self):
        self.assertFalse(is_safe_url("http://127.0.0.1"))
        self.assertFalse(is_safe_url("http://localhost"))
        self.assertFalse(is_safe_url("http://192.168.1.1"))
        self.assertFalse(is_safe_url("http://10.0.0.1"))
        self.assertFalse(is_safe_url("http://172.16.0.1"))
        self.assertFalse(is_safe_url("http://169.254.169.254")) # Cloud metadata

    def test_dns_resolution(self):
        # This test depends on DNS resolution.
        # Ideally we would mock socket.getaddrinfo, but for a quick check:
        # localhost usually resolves to 127.0.0.1
        self.assertFalse(is_safe_url("http://localhost"))

    def test_invalid_urls(self):
        self.assertFalse(is_safe_url("not_a_url"))
        self.assertFalse(is_safe_url(""))

if __name__ == '__main__':
    unittest.main()
