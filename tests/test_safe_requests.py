import unittest
from unittest.mock import patch, MagicMock
from security_utils import safe_requests_get
import requests

class TestSafeRequestsGet(unittest.TestCase):
    @patch('requests.get')
    def test_safe_url_no_redirect(self, mock_get):
        # Setup mock for a safe URL
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.history = []
        mock_get.return_value = mock_response

        # Call function
        resp = safe_requests_get("http://example.com/safe")

        # Verify
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)

    @patch('requests.get')
    def test_unsafe_initial_url(self, mock_get):
        # Should return None or raise exception before calling requests.get
        # But wait, safe_requests_get might call is_safe_url first.

        resp = safe_requests_get("http://127.0.0.1/unsafe")
        self.assertIsNone(resp)
        mock_get.assert_not_called()

    @patch('requests.get')
    def test_redirect_to_unsafe_url(self, mock_get):
        # Setup redirect chain: safe -> unsafe

        # First response: 302 Redirect to private IP
        response1 = MagicMock()
        response1.status_code = 302
        response1.headers = {'Location': 'http://169.254.169.254/secret'}
        response1.is_redirect = True

        # We expect safe_requests_get to NOT follow this if it checks the location

        # To simulate this with a loop in safe_requests_get, we return response1 first.
        # If safe_requests_get blindly followed, it would call get again.

        mock_get.side_effect = [response1]

        # Call function
        resp = safe_requests_get("http://example.com/redirect")

        # It should detect the unsafe location and stop
        self.assertIsNone(resp)
        # Should verify it didn't call get on the unsafe url
        # mock_get should have been called once with the safe url
        mock_get.assert_called_once()
        args, _ = mock_get.call_args
        self.assertEqual(args[0], "http://example.com/redirect")

    @patch('requests.get')
    def test_safe_redirect(self, mock_get):
        # Safe -> Safe

        response1 = MagicMock()
        response1.status_code = 302
        response1.headers = {'Location': 'http://example.com/final'}
        response1.is_redirect = True

        response2 = MagicMock()
        response2.status_code = 200
        response2.headers = {}
        response2.is_redirect = False

        mock_get.side_effect = [response1, response2]

        resp = safe_requests_get("http://example.com/start")

        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(mock_get.call_count, 2)

        # Verify calls
        calls = mock_get.call_args_list
        self.assertEqual(calls[0][0][0], "http://example.com/start")
        self.assertEqual(calls[1][0][0], "http://example.com/final")

if __name__ == '__main__':
    unittest.main()
