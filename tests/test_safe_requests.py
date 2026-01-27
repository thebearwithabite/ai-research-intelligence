import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import safe_requests_get, is_safe_url

class TestSafeRequestsGet(unittest.TestCase):

    @patch('security_utils.requests.get')
    def test_safe_request_no_redirect(self, mock_get):
        # Setup
        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        # Execute
        resp = safe_requests_get('https://example.com')

        # Verify
        self.assertEqual(resp, mock_resp)
        mock_get.assert_called_with('https://example.com', allow_redirects=False)

    @patch('security_utils.requests.get')
    def test_safe_request_with_safe_redirect(self, mock_get):
        # Setup
        mock_resp1 = MagicMock()
        mock_resp1.is_redirect = True
        mock_resp1.headers = {'Location': 'https://example.com/target'}

        mock_resp2 = MagicMock()
        mock_resp2.is_redirect = False
        mock_resp2.status_code = 200

        mock_get.side_effect = [mock_resp1, mock_resp2]

        # Execute
        resp = safe_requests_get('https://example.com')

        # Verify
        self.assertEqual(resp, mock_resp2)
        self.assertEqual(mock_get.call_count, 2)
        mock_get.assert_any_call('https://example.com', allow_redirects=False)
        mock_get.assert_any_call('https://example.com/target', allow_redirects=False)

    @patch('security_utils.requests.get')
    def test_safe_request_unsafe_redirect(self, mock_get):
        # Setup
        mock_resp1 = MagicMock()
        mock_resp1.is_redirect = True
        mock_resp1.headers = {'Location': 'http://127.0.0.1/admin'}

        mock_get.return_value = mock_resp1

        # Execute & Verify
        with self.assertRaises(ValueError) as cm:
            safe_requests_get('https://example.com')

        self.assertIn("Unsafe redirect", str(cm.exception))

    @patch('security_utils.requests.get')
    def test_safe_request_max_redirects(self, mock_get):
        # Setup
        mock_resp = MagicMock()
        mock_resp.is_redirect = True
        mock_resp.headers = {'Location': 'https://example.com/loop'}

        mock_get.return_value = mock_resp

        # Execute & Verify
        with self.assertRaises(requests.TooManyRedirects):
            safe_requests_get('https://example.com', max_redirects=2)

    @patch('security_utils.requests.get')
    def test_infinite_loop_detection(self, mock_get):
        # Setup
        mock_resp1 = MagicMock()
        mock_resp1.is_redirect = True
        mock_resp1.headers = {'Location': 'https://example.com/b'}

        mock_resp2 = MagicMock()
        mock_resp2.is_redirect = True
        mock_resp2.headers = {'Location': 'https://example.com/a'} # loop back to start

        mock_get.side_effect = [mock_resp1, mock_resp2]

        # Note: My implementation checks visited_urls.
        # safe_requests_get('https://example.com/a')
        # 1. get a -> redirect b. visited={a}
        # 2. get b -> redirect a. visited={a, b}
        # 3. next_url = a. a in visited -> Raise.

        with self.assertRaises(requests.TooManyRedirects) as cm:
            safe_requests_get('https://example.com/a')

        self.assertIn("Infinite redirect loop", str(cm.exception))

if __name__ == '__main__':
    unittest.main()
