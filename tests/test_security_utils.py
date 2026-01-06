import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import is_safe_url, safe_requests_get

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

class TestSafeRequestsGet(unittest.TestCase):
    @patch('requests.get')
    def test_safe_request_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        response = safe_requests_get("http://example.com")
        self.assertEqual(response, mock_response)
        mock_get.assert_called_with("http://example.com", allow_redirects=False)

    def test_unsafe_initial_url(self):
        with self.assertRaises(ValueError):
            safe_requests_get("http://127.0.0.1")

    @patch('requests.get')
    def test_safe_redirect(self, mock_get):
        # First response is a redirect
        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': 'http://example.com/target'}
        response1.url = 'http://example.com/source'

        # Second response is the destination
        response2 = MagicMock()
        response2.is_redirect = False
        response2.status_code = 200

        mock_get.side_effect = [response1, response2]

        with patch('security_utils.is_safe_url', return_value=True):
            response = safe_requests_get("http://example.com/source")
            self.assertEqual(response, response2)
            self.assertEqual(mock_get.call_count, 2)

    @patch('requests.get')
    def test_unsafe_redirect(self, mock_get):
        # First response is a redirect to a private IP
        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': 'http://127.0.0.1/admin'}
        response1.url = 'http://example.com/source'

        mock_get.return_value = response1

        # We need to ensure is_safe_url behaves correctly for the redirect
        # Mocking requests.get but letting is_safe_url run normally

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://example.com/source")

        self.assertIn("Unsafe redirect", str(cm.exception))

if __name__ == '__main__':
    unittest.main()
