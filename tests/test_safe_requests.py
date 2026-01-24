import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import safe_requests_get, is_safe_url

class TestSafeRequestsGet(unittest.TestCase):

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_redirect_followed(self, mock_is_safe, mock_get):
        # Setup
        url = "http://safe.com"
        redirect_url = "http://safe.com/redirect"

        # Mock is_safe_url to always return True
        mock_is_safe.return_value = True

        # Mock requests.get responses
        # First response: 302 Redirect
        r1 = MagicMock(spec=requests.Response)
        r1.is_redirect = True
        r1.status_code = 302
        r1.headers = {'Location': '/redirect'}
        r1.close = MagicMock()

        # Second response: 200 OK
        r2 = MagicMock(spec=requests.Response)
        r2.is_redirect = False
        r2.status_code = 200
        r2.content = b"Success"
        r2.close = MagicMock()

        mock_get.side_effect = [r1, r2]

        # Execute
        response = safe_requests_get(url)

        # Assert
        self.assertEqual(response, r2)
        self.assertEqual(mock_get.call_count, 2)

        # Check args passed to requests.get
        # allow_redirects should be False
        args, kwargs = mock_get.call_args_list[0]
        self.assertEqual(kwargs.get('allow_redirects'), False)

        # Check that is_safe_url was called for both URLs
        # Note: implementation might check urljoin result
        self.assertTrue(mock_is_safe.call_count >= 2)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_unsafe_redirect_blocked(self, mock_is_safe, mock_get):
        # Setup
        url = "http://safe.com"
        unsafe_url = "http://127.0.0.1/admin"

        # Mock is_safe_url: True for first, False for second
        def is_safe_side_effect(u):
            if u == url: return True
            return False

        mock_is_safe.side_effect = is_safe_side_effect

        # Mock requests.get response
        r1 = MagicMock(spec=requests.Response)
        r1.is_redirect = True
        r1.status_code = 302
        r1.headers = {'Location': unsafe_url}
        r1.close = MagicMock()

        mock_get.return_value = r1

        # Execute & Assert
        with self.assertRaises(ValueError) as cm:
            safe_requests_get(url)

        self.assertIn("Unsafe redirect", str(cm.exception))
        r1.close.assert_called()

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_max_redirects_exceeded(self, mock_is_safe, mock_get):
        url = "http://safe.com"
        mock_is_safe.return_value = True

        # Always redirect
        r = MagicMock(spec=requests.Response)
        r.is_redirect = True
        r.status_code = 302
        r.headers = {'Location': '/loop'}
        r.close = MagicMock()

        mock_get.return_value = r

        with self.assertRaises(requests.TooManyRedirects):
            safe_requests_get(url, max_redirects=3)

        self.assertEqual(mock_get.call_count, 4) # initial + 3 redirects

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_kwargs_passed(self, mock_is_safe, mock_get):
        url = "http://safe.com"
        mock_is_safe.return_value = True

        r = MagicMock(spec=requests.Response)
        r.is_redirect = False
        r.status_code = 200
        mock_get.return_value = r

        safe_requests_get(url, headers={'User-Agent': 'Test'}, timeout=5)

        mock_get.assert_called_with(url, allow_redirects=False, headers={'User-Agent': 'Test'}, timeout=5)

if __name__ == '__main__':
    unittest.main()
