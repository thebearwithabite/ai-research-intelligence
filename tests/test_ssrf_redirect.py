import unittest
from unittest.mock import patch, MagicMock
from security_utils import safe_requests_get, is_safe_url
import requests

class TestSSRFRedirect(unittest.TestCase):

    def test_safe_requests_get_initial_unsafe(self):
        """Test that safe_requests_get rejects an initial unsafe URL"""
        unsafe_url = "http://169.254.169.254/latest/meta-data/"

        # This checks is_safe_url logic before any request
        with self.assertRaises(ValueError) as cm:
            safe_requests_get(unsafe_url)
        self.assertIn("Unsafe URL", str(cm.exception))

    @patch('requests.Session')
    def test_safe_requests_get_redirect_unsafe(self, mock_session_cls):
        """Test that safe_requests_get rejects a redirect to an unsafe URL"""
        mock_session = mock_session_cls.return_value

        initial_url = "http://example.com/safe"
        redirect_target = "http://169.254.169.254/secret"

        # Mock response 1: Redirect
        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.status_code = 302
        resp1.headers = {'Location': redirect_target}
        resp1.close = MagicMock()

        # Mock response 2: Should not be reached
        resp2 = MagicMock()

        mock_session.get.side_effect = [resp1, resp2]

        # Mock is_safe_url to control flow
        with patch('security_utils.is_safe_url') as mock_is_safe:
            # First call (initial_url) -> True
            # Second call (redirect_target) -> False
            def side_effect(url):
                if "example.com" in url:
                    return True
                if "169.254" in url:
                    return False
                return False
            mock_is_safe.side_effect = side_effect

            with self.assertRaises(ValueError) as cm:
                safe_requests_get(initial_url)

            self.assertIn("unsafe URL", str(cm.exception))
            self.assertIn(redirect_target, str(cm.exception))

            # Verify session.get was called with allow_redirects=False
            args, kwargs = mock_session.get.call_args
            self.assertFalse(kwargs.get('allow_redirects'))

    @patch('requests.Session')
    def test_safe_requests_get_success(self, mock_session_cls):
        """Test that safe_requests_get follows safe redirects and returns content"""
        mock_session = mock_session_cls.return_value

        initial_url = "http://example.com/start"
        redirect_url = "http://example.com/final"

        # Response 1: 302 Redirect
        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.status_code = 302
        resp1.headers = {'Location': '/final'} # Relative redirect
        resp1.url = initial_url
        resp1.close = MagicMock()

        # Response 2: 200 OK
        resp2 = MagicMock()
        resp2.is_redirect = False
        resp2.status_code = 200
        resp2.content = b"Success"
        resp2.url = redirect_url

        mock_session.get.side_effect = [resp1, resp2]

        with patch('security_utils.is_safe_url', return_value=True):
            response = safe_requests_get(initial_url)

            self.assertEqual(response.content, b"Success")
            self.assertEqual(mock_session.get.call_count, 2)

if __name__ == '__main__':
    unittest.main()
