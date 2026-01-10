import unittest
from unittest.mock import MagicMock, patch
import requests
from security_utils import is_safe_url
# We import safe_requests_get later or assume it will be in security_utils
# For now, we are writing the test expecting the function to be there.

class TestSafeRequestsGet(unittest.TestCase):

    @patch('security_utils.requests.request')
    @patch('security_utils.is_safe_url')
    def test_safe_requests_get_no_redirect(self, mock_is_safe, mock_request):
        from security_utils import safe_requests_get

        # Setup
        mock_is_safe.return_value = True
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_redirect = False
        mock_request.return_value = mock_response

        # Execute
        resp = safe_requests_get("http://example.com")

        # Verify
        self.assertEqual(resp, mock_response)
        mock_is_safe.assert_called_with("http://example.com")
        mock_request.assert_called_with('GET', "http://example.com", allow_redirects=False)

    @patch('security_utils.requests.request')
    @patch('security_utils.is_safe_url')
    def test_safe_requests_get_safe_redirect(self, mock_is_safe, mock_request):
        from security_utils import safe_requests_get

        # Setup
        mock_is_safe.side_effect = [True, True] # Initial URL, Redirect URL

        # First response: 302 Redirect
        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://example.com/target'}

        # Second response: 200 OK
        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.is_redirect = False

        mock_request.side_effect = [resp1, resp2]

        # Execute
        resp = safe_requests_get("http://example.com/source")

        # Verify
        self.assertEqual(resp, resp2)
        self.assertEqual(mock_is_safe.call_count, 2)
        mock_request.assert_any_call('GET', "http://example.com/source", allow_redirects=False)
        mock_request.assert_any_call('GET', "http://example.com/target", allow_redirects=False)

    @patch('security_utils.requests.request')
    @patch('security_utils.is_safe_url')
    def test_safe_requests_get_unsafe_redirect(self, mock_is_safe, mock_request):
        from security_utils import safe_requests_get

        # Setup
        # Initial URL is safe, Redirect URL is unsafe
        mock_is_safe.side_effect = [True, False]

        # First response: 302 Redirect to unsafe location
        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://127.0.0.1/admin'}

        mock_request.return_value = resp1

        # Execute
        # Should return None or raise exception. Assuming we return None or empty object on failure as per handler.py patterns,
        # but better to raise or return None so the caller knows it failed.
        # Let's assume it returns None for now, consistent with existing code returning empty lists/strings on error.
        resp = safe_requests_get("http://example.com/source")

        # Verify
        self.assertIsNone(resp)
        self.assertEqual(mock_is_safe.call_count, 2)
        # Should not make the second request
        self.assertEqual(mock_request.call_count, 1)

    @patch('security_utils.requests.request')
    @patch('security_utils.is_safe_url')
    def test_safe_requests_get_initial_unsafe(self, mock_is_safe, mock_request):
        from security_utils import safe_requests_get

        mock_is_safe.return_value = False

        resp = safe_requests_get("http://unsafe.com")

        self.assertIsNone(resp)
        mock_request.assert_not_called()

if __name__ == '__main__':
    unittest.main()
