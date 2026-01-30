import unittest
from unittest.mock import patch, MagicMock
from security_utils import safe_requests_get
import requests

class TestSafeRequests(unittest.TestCase):
    @patch('requests.Session.get')
    def test_safe_url(self, mock_get):
        # Setup mock for safe URL
        response_ok = requests.Response()
        response_ok.status_code = 200
        response_ok._content = b"Safe content"
        response_ok.raw = MagicMock()

        mock_get.return_value = response_ok

        # Should succeed
        resp = safe_requests_get('http://example.com')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b"Safe content")

    @patch('requests.Session.get')
    def test_unsafe_initial_url(self, mock_get):
        # Initial URL is unsafe, mock shouldn't even be called
        with self.assertRaises(ValueError) as cm:
            safe_requests_get('http://127.0.0.1')
        self.assertIn("Unsafe URL", str(cm.exception))
        mock_get.assert_not_called()

    @patch('requests.Session.get')
    def test_redirect_to_unsafe(self, mock_get):
        # Setup mock to redirect to 127.0.0.1
        response_redirect = requests.Response()
        response_redirect.status_code = 302
        response_redirect.headers['Location'] = 'http://127.0.0.1/admin'
        response_redirect.raw = MagicMock()

        # We don't need a second response because it should fail before making the second call
        mock_get.return_value = response_redirect

        with self.assertRaises(ValueError) as cm:
            safe_requests_get('http://example.com')

        self.assertIn("Unsafe redirect", str(cm.exception))

    @patch('requests.Session.get')
    def test_safe_redirect(self, mock_get):
        # Setup mock to redirect to another safe URL
        response_redirect = requests.Response()
        response_redirect.status_code = 302
        response_redirect.headers['Location'] = 'http://example.org'
        response_redirect.raw = MagicMock()

        response_final = requests.Response()
        response_final.status_code = 200
        response_final._content = b"Final content"
        response_final.raw = MagicMock()

        # mock_get is called twice. First returns redirect, second returns final.
        mock_get.side_effect = [response_redirect, response_final]

        resp = safe_requests_get('http://example.com')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b"Final content")
        self.assertEqual(mock_get.call_count, 2)

    @patch('requests.Session.get')
    def test_too_many_redirects(self, mock_get):
        # Setup mock to loop redirects
        response_redirect = requests.Response()
        response_redirect.status_code = 302
        response_redirect.headers['Location'] = 'http://example.com/loop'
        response_redirect.raw = MagicMock()

        mock_get.return_value = response_redirect

        with self.assertRaises(Exception) as cm:
            safe_requests_get('http://example.com', max_redirects=2)

        self.assertIn("Too many redirects", str(cm.exception))
        self.assertEqual(mock_get.call_count, 3) # 1 initial + 2 redirects

if __name__ == '__main__':
    unittest.main()
