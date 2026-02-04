import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import safe_requests_get

class TestSafeRequestsGet(unittest.TestCase):
    @patch('requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_url_success(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = True
        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        resp = safe_requests_get("http://example.com")
        self.assertEqual(resp.status_code, 200)
        mock_is_safe_url.assert_called_with("http://example.com")

    @patch('requests.get')
    @patch('security_utils.is_safe_url')
    def test_unsafe_url_initial(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = False

        with self.assertRaisesRegex(ValueError, "Unsafe URL blocked"):
            safe_requests_get("http://unsafe.com")

    @patch('requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_redirect_to_safe(self, mock_is_safe_url, mock_get):
        # Setup: http://start.com -> http://end.com
        mock_is_safe_url.side_effect = [True, True] # Both safe

        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://end.com'}

        resp2 = MagicMock()
        resp2.is_redirect = False
        resp2.status_code = 200

        mock_get.side_effect = [resp1, resp2]

        resp = safe_requests_get("http://start.com")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(mock_get.call_count, 2)
        resp1.close.assert_called_once() # Ensure intermediate response is closed

    @patch('requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_redirect_to_unsafe(self, mock_is_safe_url, mock_get):
        # Setup: http://start.com -> http://unsafe.com
        def is_safe_side_effect(url):
            if url == "http://start.com": return True
            if url == "http://unsafe.com": return False
            return True

        mock_is_safe_url.side_effect = is_safe_side_effect

        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://unsafe.com'}

        mock_get.return_value = resp1

        with self.assertRaisesRegex(ValueError, "Unsafe URL blocked"):
            safe_requests_get("http://start.com")

        resp1.close.assert_called_once()

    @patch('requests.get')
    @patch('security_utils.is_safe_url')
    def test_too_many_redirects(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = True

        resp = MagicMock()
        resp.is_redirect = True
        resp.headers = {'Location': 'http://next.com'}

        mock_get.return_value = resp

        with self.assertRaisesRegex(ValueError, "Too many redirects"):
            safe_requests_get("http://start.com", max_redirects=2)

        self.assertEqual(mock_get.call_count, 3) # initial + 2 redirects

if __name__ == '__main__':
    unittest.main()
