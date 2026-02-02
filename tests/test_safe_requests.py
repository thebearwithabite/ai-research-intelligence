import unittest
from unittest.mock import patch, MagicMock
from security_utils import safe_requests_get, is_safe_url
import requests

class TestSafeRequests(unittest.TestCase):
    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_request_success(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = True
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        resp = safe_requests_get("http://example.com")
        self.assertEqual(resp, mock_response)
        mock_is_safe.assert_called_with("http://example.com")
        mock_get.assert_called_with("http://example.com", allow_redirects=False)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_request_unsafe_url(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = False

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://unsafe.com")
        self.assertIn("Unsafe URL", str(cm.exception))
        mock_get.assert_not_called()

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_request_redirect_success(self, mock_is_safe, mock_get):
        # Scenario: http://a.com -> 301 -> http://b.com -> 200
        mock_is_safe.side_effect = [True, True] # Both URLs are safe

        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://b.com'}

        resp2 = MagicMock()
        resp2.is_redirect = False
        resp2.status_code = 200

        mock_get.side_effect = [resp1, resp2]

        resp = safe_requests_get("http://a.com")
        self.assertEqual(resp, resp2)

        self.assertEqual(mock_get.call_count, 2)
        mock_get.assert_any_call("http://a.com", allow_redirects=False)
        mock_get.assert_any_call("http://b.com", allow_redirects=False)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_request_redirect_unsafe(self, mock_is_safe, mock_get):
        # Scenario: http://a.com -> 301 -> http://unsafe.com
        mock_is_safe.side_effect = [True, False] # Second URL is unsafe

        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://unsafe.com'}

        mock_get.return_value = resp1

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://a.com")
        self.assertIn("Unsafe URL", str(cm.exception))

        # Should have called get once for the first URL
        mock_get.assert_called_once_with("http://a.com", allow_redirects=False)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_request_redirect_loop(self, mock_is_safe, mock_get):
        # Scenario: Infinite redirects
        mock_is_safe.return_value = True

        resp = MagicMock()
        resp.is_redirect = True
        resp.headers = {'Location': 'http://a.com'}

        mock_get.return_value = resp

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://a.com", max_redirects=3)
        self.assertIn("Too many redirects", str(cm.exception))

        self.assertEqual(mock_get.call_count, 4) # initial + 3 redirects

if __name__ == '__main__':
    unittest.main()
