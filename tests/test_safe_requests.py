import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import safe_requests_get

class TestSafeRequests(unittest.TestCase):
    @patch('requests.Session')
    def test_safe_url_no_redirect(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.__enter__.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_redirect = False
        mock_session.get.return_value = mock_response

        response = safe_requests_get("https://google.com")
        self.assertEqual(response.status_code, 200)

    @patch('requests.Session')
    def test_safe_redirect(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.__enter__.return_value = mock_session

        # First response: 302 Redirect
        r1 = MagicMock()
        r1.is_redirect = True
        r1.headers = {'Location': 'https://google.com/dest'}
        r1.content = b"" # content read

        # Second response: 200 OK
        r2 = MagicMock()
        r2.is_redirect = False
        r2.status_code = 200

        mock_session.get.side_effect = [r1, r2]

        response = safe_requests_get("https://google.com/start")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_session.get.call_count, 2)

    @patch('requests.Session')
    def test_unsafe_redirect_blocked(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.__enter__.return_value = mock_session

        # First response: 302 Redirect to private IP
        r1 = MagicMock()
        r1.is_redirect = True
        r1.headers = {'Location': 'http://127.0.0.1/admin'}
        r1.content = b""

        mock_session.get.side_effect = [r1]

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("https://google.com/start")

        self.assertIn("Unsafe URL blocked", str(cm.exception))

    @patch('requests.Session')
    def test_max_redirects(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.__enter__.return_value = mock_session

        # Infinite redirect loop
        r = MagicMock()
        r.is_redirect = True
        r.headers = {'Location': 'https://google.com/loop'}
        r.content = b""

        mock_session.get.return_value = r

        with self.assertRaises(requests.TooManyRedirects):
            safe_requests_get("https://google.com/start", max_redirects=3)

        self.assertEqual(mock_session.get.call_count, 4) # initial + 3 redirects

    @patch('requests.Session')
    def test_initial_unsafe_url(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.__enter__.return_value = mock_session

        with self.assertRaises(ValueError):
            safe_requests_get("http://169.254.169.254/metadata")

        mock_session.get.assert_not_called()

if __name__ == '__main__':
    unittest.main()
