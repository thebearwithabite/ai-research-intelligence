import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import is_safe_url, safe_requests_get

class TestSSRFRedirect(unittest.TestCase):
    @patch('requests.get')
    def test_safe_requests_get_allows_safe_url(self, mock_get):
        # Setup mock for a safe URL
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"OK"
        mock_response.is_redirect = False # Explicitly set false
        mock_get.return_value = mock_response

        resp = safe_requests_get("https://google.com")
        self.assertEqual(resp.content, b"OK")

    @patch('security_utils.requests.get')
    def test_redirect_to_private_ip(self, mock_get):
        # Simulating a redirect chain: http://safe.com -> http://127.0.0.1

        # First response: 302 Redirect to localhost
        response1 = MagicMock()
        response1.status_code = 302
        response1.is_redirect = True
        response1.headers = {'Location': 'http://127.0.0.1/secret'}
        response1.url = 'http://safe.com'

        # Second response: Should not happen if blocked
        response2 = MagicMock()
        response2.status_code = 200
        response2.content = b"SECRET"

        mock_get.side_effect = [response1, response2]

        with self.assertRaises(ValueError) as cm:
            safe_requests_get('http://safe.com')

        self.assertIn("Blocked unsafe redirect", str(cm.exception))

if __name__ == '__main__':
    unittest.main()
