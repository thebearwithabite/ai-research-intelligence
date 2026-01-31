import unittest
from unittest.mock import MagicMock, patch
import requests

# We import safe_requests_get inside the test or check if it exists to avoid ImportError crashing the test run
# But for TDD, we want it to fail if it's missing.
try:
    from security_utils import safe_requests_get
except ImportError:
    safe_requests_get = None

class TestSafeRequests(unittest.TestCase):
    def setUp(self):
        if safe_requests_get is None:
            self.skipTest("safe_requests_get not implemented yet")

    @patch('requests.Session')
    def test_safe_requests_get_success(self, mock_session_cls):
        # Setup
        mock_session = mock_session_cls.return_value
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Success"
        mock_response.is_redirect = False
        # requests.Session.get returns a response
        mock_session.get.return_value = mock_response

        # Execute
        response = safe_requests_get("https://example.com")

        # Verify
        self.assertEqual(response.text, "Success")
        mock_session.get.assert_called_with("https://example.com", allow_redirects=False)

    @patch('requests.Session')
    def test_safe_requests_get_redirect_safe(self, mock_session_cls):
        # Setup
        mock_session = mock_session_cls.return_value

        # First response: 301 Redirect
        resp1 = MagicMock()
        resp1.status_code = 301
        resp1.headers = {'Location': 'https://example.com/new'}
        resp1.is_redirect = True

        # Second response: 200 OK
        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.text = "Final Destination"
        resp2.is_redirect = False

        mock_session.get.side_effect = [resp1, resp2]

        # Execute
        response = safe_requests_get("https://example.com/old")

        # Verify
        self.assertEqual(response.text, "Final Destination")
        self.assertEqual(mock_session.get.call_count, 2)
        # Check args of calls
        calls = mock_session.get.call_args_list
        self.assertEqual(calls[0][0][0], "https://example.com/old")
        self.assertEqual(calls[1][0][0], "https://example.com/new")

    @patch('requests.Session')
    def test_safe_requests_get_redirect_unsafe(self, mock_session_cls):
        # Setup
        mock_session = mock_session_cls.return_value

        # First response: 301 Redirect to localhost
        resp1 = MagicMock()
        resp1.status_code = 301
        resp1.headers = {'Location': 'http://localhost/admin'}
        resp1.is_redirect = True

        mock_session.get.side_effect = [resp1]

        # Execute & Verify
        with self.assertRaises(ValueError) as cm:
            safe_requests_get("https://example.com/vulnerable")

        self.assertIn("unsafe", str(cm.exception).lower())

    @patch('requests.Session')
    def test_safe_requests_initial_unsafe(self, mock_session_cls):
        # Execute & Verify
        with self.assertRaises(ValueError):
            safe_requests_get("http://localhost")

    @patch('requests.Session')
    def test_safe_requests_too_many_redirects(self, mock_session_cls):
        # Setup
        mock_session = mock_session_cls.return_value

        resp = MagicMock()
        resp.status_code = 301
        resp.headers = {'Location': 'https://example.com/loop'}
        resp.is_redirect = True

        mock_session.get.return_value = resp

        # Execute & Verify
        with self.assertRaises(Exception) as cm:
             safe_requests_get("https://example.com/loop", max_redirects=3)

        self.assertIn("too many redirects", str(cm.exception).lower())

if __name__ == '__main__':
    unittest.main()
