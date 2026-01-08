import unittest
from unittest.mock import MagicMock, patch
import requests
from security_utils import is_safe_url, safe_requests_get

class TestSSRFRedirect(unittest.TestCase):
    @patch('requests.get')
    def test_safe_requests_get_blocks_unsafe_redirect(self, mock_get):
        # Simulate:
        # 1. Request to http://safe.com
        # 2. Redirects to http://169.254.169.254/latest/meta-data/

        # Setup the mock to simulate a redirect
        response_redirect = MagicMock(spec=requests.Response)
        response_redirect.status_code = 302
        response_redirect.headers = {'Location': 'http://169.254.169.254/latest/meta-data/'}
        response_redirect.url = 'http://safe.com'

        # We need to simulate the loop in safe_requests_get.
        # First call returns redirect, second call (which shouldn't happen) would return sensitive data.
        mock_get.side_effect = [response_redirect]

        with self.assertRaises(ValueError) as cm:
            safe_requests_get('http://safe.com')

        self.assertIn("Unsafe URL blocked", str(cm.exception))

    @patch('requests.get')
    def test_safe_requests_get_allows_safe_redirect(self, mock_get):
        # Simulate:
        # 1. Request to http://safe.com
        # 2. Redirects to http://safe.com/final

        response_redirect = MagicMock(spec=requests.Response)
        response_redirect.status_code = 302
        response_redirect.headers = {'Location': '/final'} # Relative redirect
        response_redirect.url = 'http://safe.com'

        response_final = MagicMock(spec=requests.Response)
        response_final.status_code = 200
        response_final.url = 'http://safe.com/final'
        response_final.headers = {}

        mock_get.side_effect = [response_redirect, response_final]

        resp = safe_requests_get('http://safe.com')
        self.assertEqual(resp, response_final)

if __name__ == '__main__':
    unittest.main()
