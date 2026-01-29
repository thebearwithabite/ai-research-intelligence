import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import safe_requests_get

class TestSafeRequestsGet(unittest.TestCase):
    @patch('security_utils.is_safe_url')
    @patch('requests.get')
    def test_safe_url_success(self, mock_get, mock_is_safe):
        # Setup
        mock_is_safe.return_value = True
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_redirect = False
        mock_get.return_value = mock_response

        # Execution
        url = "https://example.com"
        response = safe_requests_get(url)

        # Verification
        self.assertEqual(response, mock_response)
        mock_get.assert_called_with(url, allow_redirects=False)

    @patch('security_utils.is_safe_url')
    def test_unsafe_url_blocked(self, mock_is_safe):
        mock_is_safe.return_value = False

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://unsafe.com")
        self.assertIn("Unsafe URL blocked", str(cm.exception))

    @patch('security_utils.is_safe_url')
    @patch('requests.get')
    def test_redirect_success(self, mock_get, mock_is_safe):
        # Setup
        mock_is_safe.return_value = True

        # First response: Redirect
        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': 'https://example.com/target'}
        response1.close = MagicMock()

        # Second response: Success
        response2 = MagicMock()
        response2.is_redirect = False
        response2.status_code = 200

        mock_get.side_effect = [response1, response2]

        # Execution
        response = safe_requests_get("https://example.com/source")

        # Verification
        self.assertEqual(response, response2)
        self.assertEqual(mock_get.call_count, 2)
        mock_get.assert_any_call("https://example.com/source", allow_redirects=False)
        mock_get.assert_any_call("https://example.com/target", allow_redirects=False)

    @patch('security_utils.is_safe_url')
    @patch('requests.get')
    def test_unsafe_redirect_blocked(self, mock_get, mock_is_safe):
        # Setup
        # is_safe_url returns True for first URL, False for second
        mock_is_safe.side_effect = [True, False]

        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': 'http://internal.ip'}

        mock_get.return_value = response1

        # Execution
        with self.assertRaises(ValueError) as cm:
            safe_requests_get("https://example.com/source")

        self.assertIn("Unsafe redirect blocked", str(cm.exception))

    @patch('security_utils.is_safe_url')
    @patch('requests.get')
    def test_too_many_redirects(self, mock_get, mock_is_safe):
        mock_is_safe.return_value = True

        response = MagicMock()
        response.is_redirect = True
        response.headers = {'Location': 'https://example.com/next'}

        mock_get.return_value = response

        with self.assertRaises(requests.TooManyRedirects):
            safe_requests_get("https://example.com", max_redirects=3)

        self.assertEqual(mock_get.call_count, 4) # initial + 3 redirects

    @patch('security_utils.is_safe_url')
    @patch('requests.get')
    def test_strip_authorization_header(self, mock_get, mock_is_safe):
        mock_is_safe.return_value = True

        # Redirect from example.com to other.com
        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': 'https://other.com/resource'}

        response2 = MagicMock()
        response2.is_redirect = False

        mock_get.side_effect = [response1, response2]

        headers = {'Authorization': 'Secret'}
        safe_requests_get("https://example.com", headers=headers)

        # Verify first call has Auth
        args1, kwargs1 = mock_get.call_args_list[0]
        self.assertEqual(kwargs1['headers']['Authorization'], 'Secret')

        # Verify second call does NOT have Auth
        args2, kwargs2 = mock_get.call_args_list[1]
        self.assertNotIn('Authorization', kwargs2['headers'])

if __name__ == '__main__':
    unittest.main()
