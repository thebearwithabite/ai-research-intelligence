import unittest
from unittest.mock import patch, MagicMock
import security_utils

# Mock the is_safe_url to avoid actual DNS lookups in these tests
# We assume is_safe_url works as tested in test_security_utils.py
class TestSafeRequests(unittest.TestCase):

    def setUp(self):
        # Patch is_safe_url to control what is considered safe/unsafe
        self.is_safe_patcher = patch('security_utils.is_safe_url')
        self.mock_is_safe = self.is_safe_patcher.start()

    def tearDown(self):
        self.is_safe_patcher.stop()

    @patch('requests.get')
    def test_safe_url_success(self, mock_get):
        # Setup
        url = "http://example.com"
        self.mock_is_safe.return_value = True

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_redirect = False
        mock_get.return_value = mock_response

        # Action
        # Note: safe_requests_get is not yet implemented, so this import might fail if I ran it now
        # But I'm writing the test first.
        # I'll rely on the plan to implement it next.
        # For now, I'll assume it will be available.
        from security_utils import safe_requests_get
        response = safe_requests_get(url)

        # Assert
        self.assertEqual(response, mock_response)
        mock_get.assert_called_with(url, allow_redirects=False)

    @patch('requests.get')
    def test_redirect_success(self, mock_get):
        # Setup
        url1 = "http://example.com"
        url2 = "http://example.com/final"

        self.mock_is_safe.side_effect = lambda u: True # All URLs safe

        # First response: 302 Redirect
        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.headers = {'Location': '/final'}
        resp1.is_redirect = True

        # Second response: 200 OK
        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.is_redirect = False
        resp2.content = b"Success"

        mock_get.side_effect = [resp1, resp2]

        from security_utils import safe_requests_get
        response = safe_requests_get(url1)

        self.assertEqual(response, resp2)
        self.assertEqual(mock_get.call_count, 2)
        # Check call args
        args_list = mock_get.call_args_list
        self.assertEqual(args_list[0][0][0], url1)
        self.assertEqual(args_list[1][0][0], url2) # Should be resolved absolute URL

    @patch('requests.get')
    def test_redirect_to_unsafe(self, mock_get):
        # Setup
        url1 = "http://example.com"
        url2 = "http://10.0.0.1/private"

        # First URL safe, second unsafe
        def is_safe_side_effect(u):
            if u == url1: return True
            if u == url2: return False
            return True
        self.mock_is_safe.side_effect = is_safe_side_effect

        # First response: 302 Redirect
        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.headers = {'Location': url2}
        resp1.is_redirect = True

        mock_get.return_value = resp1

        from security_utils import safe_requests_get

        with self.assertRaises(ValueError) as cm:
            safe_requests_get(url1)

        self.assertIn("unsafe", str(cm.exception).lower())

    def test_initial_unsafe(self):
        url = "http://10.0.0.1"
        self.mock_is_safe.return_value = False

        from security_utils import safe_requests_get

        with self.assertRaises(ValueError) as cm:
            safe_requests_get(url)

        self.assertIn("unsafe", str(cm.exception).lower())

    @patch('requests.get')
    def test_too_many_redirects(self, mock_get):
        url = "http://example.com"
        self.mock_is_safe.return_value = True

        # Infinite redirect loop
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {'Location': 'http://example.com'}
        resp.is_redirect = True

        mock_get.return_value = resp

        from security_utils import safe_requests_get

        with self.assertRaises(Exception) as cm:
            safe_requests_get(url, max_redirects=3)

        self.assertIn("too many redirects", str(cm.exception).lower())
        self.assertEqual(mock_get.call_count, 4) # initial + 3 redirects

    @patch('requests.get')
    def test_parameter_stripping_on_redirect(self, mock_get):
        url1 = "http://example.com/login"
        url2 = "http://example.com/home"

        self.mock_is_safe.return_value = True

        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.headers = {'Location': url2}
        resp1.is_redirect = True

        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.is_redirect = False

        mock_get.side_effect = [resp1, resp2]

        from security_utils import safe_requests_get

        safe_requests_get(url1, json={'secret': '123'})

        # First call has json
        self.assertEqual(mock_get.call_args_list[0][1]['json'], {'secret': '123'})

        # Second call (redirect) should NOT have json
        self.assertNotIn('json', mock_get.call_args_list[1][1])

if __name__ == '__main__':
    unittest.main()
