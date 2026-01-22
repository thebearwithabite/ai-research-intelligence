import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import safe_requests_get

class TestSafeRequestsGet(unittest.TestCase):
    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_direct_success(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = True
        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        resp = safe_requests_get("http://example.com")
        self.assertEqual(resp, mock_resp)
        # Verify allow_redirects=False was passed
        self.assertEqual(mock_get.call_args[1]['allow_redirects'], False)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_redirect(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = True

        # First response: 302 Redirect
        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://example.com/dest'}

        # Second response: 200 OK
        resp2 = MagicMock()
        resp2.is_redirect = False
        resp2.status_code = 200

        mock_get.side_effect = [resp1, resp2]

        resp = safe_requests_get("http://example.com")
        self.assertEqual(resp, resp2)
        self.assertEqual(mock_get.call_count, 2)

        # Check call arguments
        calls = mock_get.call_args_list
        self.assertEqual(calls[0][0][0], "http://example.com")
        self.assertEqual(calls[1][0][0], "http://example.com/dest")
        self.assertEqual(calls[1][1]['allow_redirects'], False)

        # Verify intermediate response closed
        resp1.close.assert_called_once()

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_unsafe_redirect(self, mock_is_safe, mock_get):
        # First URL is safe
        # Redirect URL is unsafe (e.g. localhost)
        mock_is_safe.side_effect = [True, False]

        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://localhost'}

        mock_get.return_value = resp1

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://example.com")

        self.assertIn("Unsafe URL blocked", str(cm.exception))

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_max_redirects(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = True

        resp = MagicMock()
        resp.is_redirect = True
        resp.headers = {'Location': 'http://example.com/loop'}

        mock_get.return_value = resp

        with self.assertRaises(requests.exceptions.TooManyRedirects):
            safe_requests_get("http://example.com", max_redirects=3)

        # Initial call + 3 redirects + 1 extra check?
        # range(max_redirects + 1) means 0, 1, 2, 3 (4 iterations)
        # Iteration 0: Request 1 (Redirect)
        # Iteration 1: Request 2 (Redirect)
        # Iteration 2: Request 3 (Redirect)
        # Iteration 3: Request 4 (Redirect) -> Raise TooManyRedirects?
        # My code: for _ in range(max_redirects + 1):
        # If max_redirects=3, range is 4.
        # It allows 3 redirects (4 requests total).
        # If the 4th request is ALSO a redirect, then loop finishes and raises.
        # So call_count should be 4.
        self.assertEqual(mock_get.call_count, 4)

if __name__ == '__main__':
    unittest.main()
