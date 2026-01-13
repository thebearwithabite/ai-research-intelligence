import unittest
from unittest.mock import patch, MagicMock
import requests
from security_utils import is_safe_url, safe_requests_get
import socket

class TestSSRFRedirect(unittest.TestCase):
    @patch('socket.getaddrinfo')
    def test_safe_requests_get_blocks_unsafe_redirect(self, mock_getaddrinfo):
        # Setup DNS resolution
        def side_effect(host, port, family=0, type=0, proto=0, flags=0):
            if host == "malicious.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 80))]
            if host == "internal.service":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 80))]
            raise socket.gaierror("Name or service not known")

        mock_getaddrinfo.side_effect = side_effect

        # Initial URL
        url = "http://malicious.com"

        # Mock requests.get
        with patch('requests.get') as mock_get:
            # First response: 302 Redirect to internal.service
            response1 = requests.Response()
            response1.status_code = 302
            response1.headers['Location'] = 'http://internal.service/secret'
            response1.url = 'http://malicious.com'
            # We don't set is_redirect because it is a property that checks status_code

            mock_get.return_value = response1

            with self.assertRaises(ValueError) as cm:
                safe_requests_get(url)

            self.assertIn("Unsafe redirect to", str(cm.exception))
            print("\n[SUCCESS] safe_requests_get blocked unsafe redirect!")

    @patch('socket.getaddrinfo')
    def test_safe_requests_get_follows_safe_redirect(self, mock_getaddrinfo):
        # Setup DNS resolution
        def side_effect(host, port, family=0, type=0, proto=0, flags=0):
            if host == "good.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 80))]
            if host == "also-good.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('5.6.7.8', 80))]
            raise socket.gaierror("Name or service not known")

        mock_getaddrinfo.side_effect = side_effect

        url = "http://good.com"

        with patch('requests.get') as mock_get:
            # First response: 302 Redirect to also-good.com
            response1 = requests.Response()
            response1.status_code = 302
            response1.headers['Location'] = 'http://also-good.com/data'
            response1.url = 'http://good.com'

            # Second response: 200 OK
            response2 = requests.Response()
            response2.status_code = 200
            response2._content = b"SAFE_DATA"
            response2.url = 'http://also-good.com/data'
            response2.encoding = 'utf-8' # for .text

            mock_get.side_effect = [response1, response2]

            resp = safe_requests_get(url)

            self.assertEqual(resp.text, "SAFE_DATA")
            self.assertEqual(resp.url, "http://also-good.com/data")
            # Verify history
            self.assertEqual(len(resp.history), 1)
            self.assertEqual(resp.history[0], response1)
            print("\n[SUCCESS] safe_requests_get followed safe redirect!")

if __name__ == '__main__':
    unittest.main()
