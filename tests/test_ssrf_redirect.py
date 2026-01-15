import unittest
from unittest.mock import patch, MagicMock
import requests
# We will import safe_requests_get after implementing it,
# for now we can test the concept or just placeholder.
# Actually, I'll write the test expecting the function to be there.
# If I run it before implementation, it will error on import.
try:
    from security_utils import safe_requests_get
except ImportError:
    safe_requests_get = None

class TestSSRFRedirect(unittest.TestCase):
    def setUp(self):
        if safe_requests_get is None:
            self.skipTest("safe_requests_get not implemented yet")

    @patch('requests.get')
    def test_redirect_to_unsafe_url(self, mock_get):
        # Setup mock to simulate a redirect to localhost
        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': 'http://localhost/secret'}
        response1.status_code = 302

        # The mocked get should respect allow_redirects=False if our code sets it
        # But here we just return the 302 response immediately.

        mock_get.return_value = response1

        # The initial URL is safe
        safe_url = "http://example.com/safe"

        # This should raise an error because the redirect is unsafe
        # We assume safe_requests_get raises ValueError for unsafe redirects
        with self.assertRaises(ValueError) as cm:
             safe_requests_get(safe_url)

        # We expect the error message to indicate unsafe URL
        self.assertTrue("Unsafe URL" in str(cm.exception) or "blocked" in str(cm.exception).lower())

    @patch('requests.get')
    def test_safe_redirect(self, mock_get):
        # Setup mock: Redirect -> Safe URL -> 200 OK
        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': 'http://example.com/final'}
        response1.status_code = 302

        response2 = MagicMock()
        response2.is_redirect = False
        response2.status_code = 200
        response2.text = "Success"

        mock_get.side_effect = [response1, response2]

        safe_url = "http://example.com/start"

        response = safe_requests_get(safe_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "Success")

        # Verify allow_redirects=False was used
        call_args = mock_get.call_args_list[0]
        self.assertFalse(call_args[1].get('allow_redirects'))

if __name__ == '__main__':
    unittest.main()
