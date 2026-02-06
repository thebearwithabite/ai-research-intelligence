import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import safe_requests_get

class TestSafeRequestsGet(unittest.TestCase):
    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_request_success(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = True
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        response = safe_requests_get("http://example.com")
        self.assertEqual(response, mock_response)
        mock_is_safe.assert_called_with("http://example.com")

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_unsafe_url(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = False
        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://unsafe.com")
        self.assertIn("Unsafe URL detected", str(cm.exception))

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_redirect_success(self, mock_is_safe, mock_get):
        # Setup: url1 -> redirect -> url2 -> success
        mock_is_safe.side_effect = [True, True] # Both URLs are safe

        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': 'http://example.com/dest'}

        response2 = MagicMock()
        response2.is_redirect = False
        response2.status_code = 200

        mock_get.side_effect = [response1, response2]

        response = safe_requests_get("http://example.com/start")
        self.assertEqual(response, response2)
        self.assertEqual(mock_get.call_count, 2)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_redirect_to_unsafe(self, mock_is_safe, mock_get):
        # Setup: url1 -> redirect -> unsafe_url
        mock_is_safe.side_effect = [True, False] # First safe, second unsafe

        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': 'http://internal.com'}

        mock_get.return_value = response1

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://example.com")
        self.assertIn("Unsafe URL detected", str(cm.exception))

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_max_redirects_exceeded(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = True

        # Create a redirect loop or chain
        response = MagicMock()
        response.is_redirect = True
        response.headers = {'Location': 'http://example.com/next'}

        mock_get.return_value = response

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://example.com", max_redirects=3)
        self.assertIn("Too many redirects", str(cm.exception))
        self.assertEqual(mock_get.call_count, 4) # initial + 3 redirects

if __name__ == '__main__':
    unittest.main()
