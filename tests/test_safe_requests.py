import unittest
from unittest.mock import patch, MagicMock
# We import safe_requests_get from security_utils.
# It might not exist yet, so this test will fail until we implement it.
try:
    from security_utils import safe_requests_get
except ImportError:
    safe_requests_get = None

class TestSafeRequestsGet(unittest.TestCase):
    def setUp(self):
        if safe_requests_get is None:
            self.skipTest("safe_requests_get not implemented yet")

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_safe_redirect(self, mock_is_safe_url, mock_get):
        # Setup: URL1 -> Redirect -> URL2 (Safe)
        mock_is_safe_url.return_value = True

        response1 = MagicMock()
        response1.status_code = 302
        response1.headers = {'Location': 'http://example.com/safe'}
        response1.is_redirect = True

        response2 = MagicMock()
        response2.status_code = 200
        response2.is_redirect = False
        response2.headers = {}
        response2.content = b"Success"

        mock_get.side_effect = [response1, response2]

        resp = safe_requests_get('http://example.com/start')

        self.assertEqual(resp.content, b"Success")
        self.assertEqual(mock_get.call_count, 2)

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_unsafe_redirect(self, mock_is_safe_url, mock_get):
        # Setup: URL1 -> Redirect -> URL2 (Unsafe)

        # is_safe_url returns True for first URL, False for second
        def is_safe_side_effect(url):
            if 'unsafe' in url:
                return False
            return True
        mock_is_safe_url.side_effect = is_safe_side_effect

        response1 = MagicMock()
        response1.status_code = 302
        response1.headers = {'Location': 'http://example.com/unsafe'}

        mock_get.return_value = response1

        # Expect an error or None. Let's decide to raise ValueError for unsafe redirect.
        with self.assertRaises(ValueError):
            safe_requests_get('http://example.com/start')

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_max_redirects(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = True

        response = MagicMock()
        response.status_code = 302
        response.headers = {'Location': 'http://example.com/next'}

        mock_get.return_value = response

        with self.assertRaises(ValueError): # Too many redirects
            safe_requests_get('http://example.com/start', max_redirects=3)

        self.assertEqual(mock_get.call_count, 4) # initial + 3 redirects

    @patch('security_utils.requests.get')
    @patch('security_utils.is_safe_url')
    def test_stream_support(self, mock_is_safe_url, mock_get):
        mock_is_safe_url.return_value = True

        response = MagicMock()
        response.status_code = 200
        response.is_redirect = False
        response.headers = {}
        response.iter_content = MagicMock()

        mock_get.return_value = response

        safe_requests_get('http://example.com/stream', stream=True)

        mock_get.assert_called_with('http://example.com/stream', allow_redirects=False, stream=True)

if __name__ == '__main__':
    unittest.main()
