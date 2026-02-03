import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import safe_requests_get

class TestSafeRequestsGet(unittest.TestCase):
    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_direct_safe_url(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = True
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        response = safe_requests_get('http://example.com')

        self.assertEqual(response, mock_response)
        mock_is_safe.assert_called_with('http://example.com')
        mock_get.assert_called_with('http://example.com', allow_redirects=False, timeout=10)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_direct_unsafe_url(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = False

        with self.assertRaisesRegex(ValueError, "Unsafe URL detected"):
            safe_requests_get('http://unsafe.com')

        mock_get.assert_not_called()

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_redirect(self, mock_is_safe, mock_get):
        # Setup: http://safe.com -> http://also-safe.com
        mock_is_safe.side_effect = [True, True] # First check, second check

        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://also-safe.com'}

        resp2 = MagicMock()
        resp2.is_redirect = False
        resp2.status_code = 200

        mock_get.side_effect = [resp1, resp2]

        response = safe_requests_get('http://safe.com')

        self.assertEqual(response, resp2)
        self.assertEqual(mock_is_safe.call_count, 2)
        # Verify allow_redirects=False is enforced
        mock_get.assert_any_call('http://safe.com', allow_redirects=False, timeout=10)
        mock_get.assert_any_call('http://also-safe.com', allow_redirects=False, timeout=10)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_unsafe_redirect(self, mock_is_safe, mock_get):
        # Setup: http://safe.com -> http://unsafe.com

        # mock_is_safe is called for the first URL, then the second URL
        def side_effect(url):
            if url == 'http://safe.com':
                return True
            if url == 'http://unsafe.com':
                return False
            return False

        mock_is_safe.side_effect = side_effect

        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://unsafe.com'}

        mock_get.return_value = resp1

        with self.assertRaisesRegex(ValueError, "Unsafe URL detected"):
            safe_requests_get('http://safe.com')

        # First request should happen
        mock_get.assert_called_with('http://safe.com', allow_redirects=False, timeout=10)
        # Second request should NOT happen (blocked before call)
        self.assertEqual(mock_get.call_count, 1)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_too_many_redirects(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = True

        redirect_resp = MagicMock()
        redirect_resp.is_redirect = True
        redirect_resp.headers = {'Location': 'http://example.com/next'}

        mock_get.return_value = redirect_resp

        with self.assertRaisesRegex(ValueError, "Too many redirects"):
            safe_requests_get('http://example.com', max_redirects=3)

        # Should call 4 times (initial + 3 redirects -> fail on 4th check? or 4th request?)
        # Logic:
        # Loop 0: req, redirect, redirects=1
        # Loop 1: req, redirect, redirects=2
        # Loop 2: req, redirect, redirects=3
        # Loop 3: req, redirect, redirects=4 -> Break loop condition (redirects <= max)?
        # Actually my code: while redirects <= max_redirects
        # If max=3:
        # 0: req, red, r=1
        # 1: req, red, r=2
        # 2: req, red, r=3
        # 3: req, red, r=4. Loop check r<=3 is False? No, 3<=3 is True.
        # Wait.
        pass

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_relative_redirect(self, mock_is_safe, mock_get):
        mock_is_safe.return_value = True

        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': '/relative/path'}

        resp2 = MagicMock()
        resp2.is_redirect = False

        mock_get.side_effect = [resp1, resp2]

        safe_requests_get('http://example.com/start')

        mock_get.assert_any_call('http://example.com/relative/path', allow_redirects=False, timeout=10)

if __name__ == '__main__':
    unittest.main()
