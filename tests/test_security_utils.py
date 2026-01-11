import unittest
from unittest.mock import patch, MagicMock
from security_utils import safe_requests_get, is_safe_url
import requests

class TestSecurityUtils(unittest.TestCase):
    def test_is_safe_url_private_ip(self):
        self.assertFalse(is_safe_url("http://127.0.0.1"))
        self.assertFalse(is_safe_url("http://192.168.1.1"))
        self.assertFalse(is_safe_url("http://10.0.0.1"))

    def test_is_safe_url_public_ip(self):
        # We need to mock socket.getaddrinfo to avoid actual DNS lookups and ensure consistent results
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(2, 1, 6, '', ('8.8.8.8', 80))]
            self.assertTrue(is_safe_url("http://google.com"))

    @patch('requests.Session.request')
    def test_safe_requests_get_follows_safe_redirect(self, mock_request):
        # Setup redirect chain: http://safe.com -> http://also-safe.com/resource
        response1 = MagicMock()
        response1.is_redirect = True
        response1.status_code = 302
        response1.headers = {'Location': 'http://also-safe.com/resource'}

        response2 = MagicMock()
        response2.is_redirect = False
        response2.status_code = 200
        response2.text = "Success"

        mock_request.side_effect = [response1, response2]

        with patch('security_utils.is_safe_url') as mock_is_safe:
            mock_is_safe.return_value = True

            resp = safe_requests_get("http://safe.com")

            self.assertEqual(resp.text, "Success")
            self.assertEqual(mock_request.call_count, 2)

    @patch('requests.Session.request')
    def test_safe_requests_get_blocks_unsafe_redirect(self, mock_request):
        # Setup redirect chain: http://safe.com -> http://127.0.0.1/admin
        response1 = MagicMock()
        response1.is_redirect = True
        response1.status_code = 302
        response1.headers = {'Location': 'http://127.0.0.1/admin'}

        mock_request.return_value = response1

        # Real is_safe_url will catch the localhost IP
        with patch('security_utils.is_safe_url') as mock_is_safe:
            # First call (original URL) is safe
            # Second call (redirect URL) is UNSAFE
            mock_is_safe.side_effect = [True, False]

            with self.assertRaises(ValueError) as cm:
                safe_requests_get("http://safe.com")

            self.assertIn("Redirection to unsafe URL", str(cm.exception))

if __name__ == '__main__':
    unittest.main()
