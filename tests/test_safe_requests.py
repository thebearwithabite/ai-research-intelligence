import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import safe_requests_get, is_safe_url

class TestSafeRequestsGet(unittest.TestCase):
    @patch('security_utils.requests.Session')
    def test_safe_redirect_flow(self, mock_session_cls):
        # Scenario: https://safe.com -> (302) -> https://also-safe.com -> (200)
        mock_session = mock_session_cls.return_value

        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.headers = {'Location': 'https://also-safe.com'}
        resp1.is_redirect = True

        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.is_redirect = False
        resp2.content = b"Success"

        mock_session.get.side_effect = [resp1, resp2]

        # Mock is_safe_url to allow these URLs
        with patch('security_utils.is_safe_url') as mock_is_safe:
            mock_is_safe.side_effect = lambda url: True

            response = safe_requests_get('https://safe.com')

            self.assertIsNotNone(response)
            self.assertEqual(response.content, b"Success")
            self.assertEqual(mock_session.get.call_count, 2)

    @patch('security_utils.requests.Session')
    def test_unsafe_redirect(self, mock_session_cls):
        # Scenario: https://safe.com -> (302) -> http://127.0.0.1/admin
        mock_session = mock_session_cls.return_value

        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.headers = {'Location': 'http://127.0.0.1/admin'}
        resp1.is_redirect = True

        mock_session.get.side_effect = [resp1]

        # Mock is_safe_url to simulate the check
        with patch('security_utils.is_safe_url') as mock_is_safe:
            def side_effect(url):
                if "127.0.0.1" in url:
                    return False
                return True
            mock_is_safe.side_effect = side_effect

            with self.assertRaises(ValueError) as cm:
                safe_requests_get('https://safe.com')

            self.assertIn("Unsafe redirect URL", str(cm.exception))
            # Should not have called get for the second URL
            self.assertEqual(mock_session.get.call_count, 1)

    @patch('security_utils.requests.Session')
    def test_initial_unsafe_url(self, mock_session_cls):
        mock_session = mock_session_cls.return_value

        with patch('security_utils.is_safe_url') as mock_is_safe:
            mock_is_safe.return_value = False

            with self.assertRaises(ValueError) as cm:
                safe_requests_get('http://unsafe.com')

            self.assertIn("Unsafe URL", str(cm.exception))
            mock_session.get.assert_not_called()

if __name__ == '__main__':
    unittest.main()
