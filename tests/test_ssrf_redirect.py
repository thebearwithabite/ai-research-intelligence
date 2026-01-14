import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import safe_requests_get, is_safe_url

class TestSafeRequestsGet(unittest.TestCase):

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_redirect(self, mock_is_safe_url, mock_get):
        # Mock is_safe_url to return True for all checked URLs
        mock_is_safe_url.side_effect = lambda u: True

        # Setup mock responses
        # First response: 302 Redirect
        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://example.com/dest'}
        resp1.status_code = 302

        # Second response: 200 OK
        resp2 = MagicMock()
        resp2.is_redirect = False
        resp2.status_code = 200
        resp2.text = "Success"

        mock_get.side_effect = [resp1, resp2]

        final_resp = safe_requests_get("http://example.com/start")

        self.assertEqual(final_resp, resp2)
        self.assertEqual(mock_get.call_count, 2)
        # Verify allow_redirects=False was used
        self.assertFalse(mock_get.call_args_list[0][1]['allow_redirects'])

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_unsafe_redirect_blocked(self, mock_is_safe_url, mock_get):
        # Url 1 is safe, Url 2 is unsafe
        def fake_is_safe(url):
            if "unsafe" in url:
                return False
            return True
        mock_is_safe_url.side_effect = fake_is_safe

        # First response: 302 Redirect to unsafe
        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://unsafe.com/admin'}
        resp1.status_code = 302

        mock_get.return_value = resp1

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://safe.com/start")

        self.assertIn("Blocked unsafe URL", str(cm.exception))
        # Should only call get once (for the first URL)
        self.assertEqual(mock_get.call_count, 1)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_too_many_redirects(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = True

        resp = MagicMock()
        resp.is_redirect = True
        resp.headers = {'Location': 'http://example.com/loop'}

        mock_get.return_value = resp

        with self.assertRaises(requests.TooManyRedirects):
            safe_requests_get("http://example.com", max_redirects=3)

        self.assertEqual(mock_get.call_count, 4) # initial + 3 redirects

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_clears_params_after_redirect(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = True

        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://example.com/next'}

        resp2 = MagicMock()
        resp2.is_redirect = False

        mock_get.side_effect = [resp1, resp2]

        safe_requests_get("http://example.com", params={'key': 'val'})

        # First call should have params
        args1, kwargs1 = mock_get.call_args_list[0]
        self.assertEqual(kwargs1['params'], {'key': 'val'})

        # Second call should NOT have params
        args2, kwargs2 = mock_get.call_args_list[1]
        self.assertNotIn('params', kwargs2)

if __name__ == '__main__':
    unittest.main()
