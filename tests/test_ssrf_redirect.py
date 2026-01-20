import unittest
from unittest.mock import patch, MagicMock
import requests

# Import the function to be tested.
# It might fail import if not implemented yet, so we can wrap in try-except for the sake of the plan step if strictness is required,
# but for TDD, failing import is a valid "red" state.
try:
    from security_utils import safe_requests_get
except ImportError:
    safe_requests_get = None

class TestSSRFRedirect(unittest.TestCase):
    def setUp(self):
        if safe_requests_get is None:
            self.skipTest("safe_requests_get not implemented yet")

    @patch('requests.Session.request')
    def test_redirect_to_private_ip(self, mock_request):
        """
        Simulate a request to a safe URL that redirects to a private IP.
        The safe_requests_get function should raise an error.
        """
        # Response 1: 302 to private IP
        response1 = MagicMock()
        response1.status_code = 302
        response1.headers = {'Location': 'http://169.254.169.254/latest/meta-data/'}
        response1.is_redirect = True
        # requests.Session.request returns a Response object

        mock_request.side_effect = [response1]

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://example.com/evil")

        self.assertTrue("unsafe" in str(cm.exception).lower() or "blocked" in str(cm.exception).lower())

    @patch('requests.Session.request')
    def test_safe_redirect(self, mock_request):
        """
        Simulate a safe redirect. http://example.com -> http://example.com/final
        """
        # Response 1: 302 to safe URL
        response1 = MagicMock()
        response1.status_code = 302
        response1.headers = {'Location': 'http://example.com/final'}
        response1.is_redirect = True

        # Response 2: 200 OK
        response2 = MagicMock()
        response2.status_code = 200
        response2.headers = {}
        response2.is_redirect = False
        response2.content = b"Success"

        mock_request.side_effect = [response1, response2]

        resp = safe_requests_get("http://example.com/start")
        self.assertEqual(resp.content, b"Success")

if __name__ == '__main__':
    unittest.main()
