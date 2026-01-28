import unittest
from unittest.mock import patch, MagicMock
from security_utils import is_safe_url, safe_requests_get
import requests

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
    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_request_success(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = True
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        response = safe_requests_get("http://example.com")
        self.assertEqual(response, mock_response)
        mock_is_safe_url.assert_called_with("http://example.com")
        mock_get.assert_called_with("http://example.com", allow_redirects=False)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_request_redirect(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = True

        # First response: Redirect
        mock_resp1 = MagicMock()
        mock_resp1.is_redirect = True
        mock_resp1.headers = {'Location': 'http://example.com/new'}

        # Second response: Success
        mock_resp2 = MagicMock()
        mock_resp2.is_redirect = False
        mock_resp2.status_code = 200

        mock_get.side_effect = [mock_resp1, mock_resp2]

        response = safe_requests_get("http://example.com")
        self.assertEqual(response, mock_resp2)

        self.assertEqual(mock_is_safe_url.call_count, 2)
        mock_get.assert_any_call("http://example.com", allow_redirects=False)
        mock_get.assert_any_call("http://example.com/new", allow_redirects=False)

    @patch('security_utils.is_safe_url')
    def test_unsafe_url_initial(self, mock_is_safe_url):
        mock_is_safe_url.return_value = False
        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://unsafe.com")
        self.assertIn("Unsafe URL", str(cm.exception))

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_unsafe_url_redirect(self, mock_is_safe_url, mock_get):
        # Allow first URL, deny second
        mock_is_safe_url.side_effect = [True, False]

        mock_resp1 = MagicMock()
        mock_resp1.is_redirect = True
        mock_resp1.headers = {'Location': 'http://unsafe.com'}
        mock_get.return_value = mock_resp1

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://safe.com")
        self.assertIn("Unsafe URL", str(cm.exception))

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_too_many_redirects(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = True

        mock_resp = MagicMock()
        mock_resp.is_redirect = True
        mock_resp.headers = {'Location': 'http://example.com/loop'}
        mock_get.return_value = mock_resp

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://example.com", max_redirects=2)
        self.assertIn("Too many redirects", str(cm.exception))

if __name__ == '__main__':
    unittest.main()
