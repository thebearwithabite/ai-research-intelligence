import unittest
from unittest.mock import MagicMock, patch
import requests
from security_utils import safe_requests_get, is_safe_url

class TestSafeRequestsGet(unittest.TestCase):

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_request_no_redirect(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = True
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_get.return_value = mock_response

        url = "http://example.com"
        response = safe_requests_get(url)

        self.assertEqual(response, mock_response)
        mock_is_safe_url.assert_called_with(url)
        mock_get.assert_called_with(url, allow_redirects=False)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_unsafe_initial_url(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = False

        with self.assertRaises(ValueError):
            safe_requests_get("http://unsafe.com")

        mock_get.assert_not_called()

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_redirect(self, mock_is_safe_url, mock_get):
        # Setup mocks
        url1 = "http://example.com"
        url2 = "http://example.com/redirected"

        # is_safe_url should be called for both URLs
        mock_is_safe_url.side_effect = lambda u: u in [url1, url2]

        # First response is a redirect
        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': url2}

        # Second response is final
        response2 = MagicMock()
        response2.is_redirect = False

        mock_get.side_effect = [response1, response2]

        response = safe_requests_get(url1)

        self.assertEqual(response, response2)
        self.assertEqual(mock_get.call_count, 2)
        # Verify calls
        mock_get.assert_any_call(url1, allow_redirects=False)
        mock_get.assert_any_call(url2, allow_redirects=False)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_unsafe_redirect(self, mock_is_safe_url, mock_get):
        url1 = "http://example.com"
        url2 = "http://unsafe.com"

        # url1 is safe, url2 is unsafe
        def is_safe(u):
            if u == url1: return True
            if u == url2: return False
            return False
        mock_is_safe_url.side_effect = is_safe

        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': url2}

        mock_get.return_value = response1

        with self.assertRaises(ValueError) as cm:
            safe_requests_get(url1)

        self.assertIn("Unsafe redirect", str(cm.exception))
        mock_get.assert_called_once() # Should stop after first request

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_relative_redirect(self, mock_is_safe_url, mock_get):
        url1 = "http://example.com/page"
        redirect_loc = "/login"
        url2 = "http://example.com/login"

        mock_is_safe_url.return_value = True

        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': redirect_loc}

        response2 = MagicMock()
        response2.is_redirect = False

        mock_get.side_effect = [response1, response2]

        safe_requests_get(url1)

        mock_get.assert_any_call(url1, allow_redirects=False)
        mock_get.assert_any_call(url2, allow_redirects=False)

if __name__ == '__main__':
    unittest.main()
