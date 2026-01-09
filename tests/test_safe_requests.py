import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import safe_requests_get

class TestSafeRequestsGet(unittest.TestCase):

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_request_success(self, mock_is_safe_url, mock_get):
        """Test a simple successful request to a safe URL."""
        mock_is_safe_url.return_value = True

        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        url = "https://example.com"
        resp = safe_requests_get(url)

        self.assertEqual(resp, mock_resp)
        mock_is_safe_url.assert_called_with(url)
        mock_get.assert_called_with(url, allow_redirects=False)

    @patch('security_utils.is_safe_url')
    def test_unsafe_initial_url(self, mock_is_safe_url):
        """Test that an initially unsafe URL is blocked."""
        mock_is_safe_url.return_value = False

        url = "http://unsafe.local"

        with self.assertRaises(ValueError) as cm:
            safe_requests_get(url)

        self.assertIn("Unsafe URL detected", str(cm.exception))

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_redirect_to_unsafe_url(self, mock_is_safe_url, mock_get):
        """Test that a redirect to an unsafe URL is blocked."""
        # Setup: safe -> unsafe
        url1 = "https://safe.com"
        url2 = "http://unsafe.local"

        # is_safe_url calls: first for url1 (True), then for url2 (False)
        mock_is_safe_url.side_effect = [True, False]

        # First request returns a redirect
        mock_resp1 = MagicMock()
        mock_resp1.is_redirect = True
        mock_resp1.headers = {'Location': url2}
        mock_resp1.close = MagicMock()

        mock_get.return_value = mock_resp1

        with self.assertRaises(ValueError) as cm:
            safe_requests_get(url1)

        self.assertIn("Unsafe URL detected", str(cm.exception))
        # Verify first response was closed
        mock_resp1.close.assert_called()

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_redirect_chain(self, mock_is_safe_url, mock_get):
        """Test a valid chain of redirects."""
        url1 = "https://one.com"
        url2 = "https://two.com"
        url3 = "https://three.com"

        # All URLs are safe
        mock_is_safe_url.return_value = True

        # Resp 1: Redirect to url2
        mock_resp1 = MagicMock()
        mock_resp1.is_redirect = True
        mock_resp1.headers = {'Location': url2}

        # Resp 2: Redirect to url3
        mock_resp2 = MagicMock()
        mock_resp2.is_redirect = True
        mock_resp2.headers = {'Location': url3}

        # Resp 3: Final response
        mock_resp3 = MagicMock()
        mock_resp3.is_redirect = False
        mock_resp3.status_code = 200

        mock_get.side_effect = [mock_resp1, mock_resp2, mock_resp3]

        resp = safe_requests_get(url1)

        self.assertEqual(resp, mock_resp3)
        self.assertEqual(mock_get.call_count, 3)
        # Check history was populated (though we mock the objects, the function populates history)
        # Our implementation creates a new history list.
        # Since we are mocking the return value, the history attribute on mock_resp3 is set by safe_requests_get
        self.assertEqual(len(resp.history), 2)
        self.assertEqual(resp.history[0], mock_resp1)
        self.assertEqual(resp.history[1], mock_resp2)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_too_many_redirects(self, mock_is_safe_url, mock_get):
        """Test that exceeding max redirects raises an error."""
        mock_is_safe_url.return_value = True

        # Create a redirect loop or just many redirects
        mock_resp = MagicMock()
        mock_resp.is_redirect = True
        mock_resp.headers = {'Location': 'https://next.com'}

        mock_get.return_value = mock_resp

        with self.assertRaises(requests.TooManyRedirects):
            safe_requests_get("https://start.com", max_redirects=3)

        # Should have called get 4 times (1 initial + 3 redirects)
        self.assertEqual(mock_get.call_count, 4)

if __name__ == '__main__':
    unittest.main()
