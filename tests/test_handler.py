import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import socket

# Add repo root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from handler import extract_substack_content, is_safe_url

class TestHandlerSecurity(unittest.TestCase):

    @patch('feedparser.parse')
    @patch('requests.get')
    def test_ssrf_blocked_in_extract(self, mock_get, mock_parse):
        # Setup mock feed with malicious link
        mock_entry = MagicMock()
        mock_entry.link = "http://169.254.169.254/latest/meta-data/"
        mock_entry.title = "Sensitive Data"
        mock_entry.get = lambda k, d=None: getattr(mock_entry, k, d)

        mock_feed = MagicMock()
        mock_feed.entries = [mock_entry]
        mock_parse.return_value = mock_feed

        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        # Use a context manager to mock socket.gethostbyname
        with patch('socket.gethostbyname') as mock_socket:
            def side_effect(hostname):
                if hostname == "169.254.169.254":
                    return "169.254.169.254"
                return "93.184.216.34" # example.com
            mock_socket.side_effect = side_effect

            # Run extraction
            posts = extract_substack_content("https://safe-site.com")

        # Verify that requests.get was NOT called
        mock_get.assert_not_called()

    def test_is_safe_url(self):
        # Safe URLs
        with patch('socket.gethostbyname') as mock_socket:
            mock_socket.return_value = "93.184.216.34"
            self.assertTrue(is_safe_url("https://google.com"))

        # Unsafe schemes
        self.assertFalse(is_safe_url("file:///etc/passwd"))

        # Unsafe IPs
        with patch('socket.gethostbyname') as mock_socket:
            # Localhost
            mock_socket.return_value = "127.0.0.1"
            self.assertFalse(is_safe_url("http://localhost"))

            # Private IP
            mock_socket.return_value = "192.168.1.1"
            self.assertFalse(is_safe_url("http://internal-router"))

            # Link local
            mock_socket.return_value = "169.254.169.254"
            self.assertFalse(is_safe_url("http://metadata-server"))

    @patch('feedparser.parse')
    @patch('requests.get')
    def test_valid_scrape(self, mock_get, mock_parse):
        # Setup mock feed with valid URL
        mock_entry = MagicMock()
        mock_entry.link = "https://valid-site.com/post/1"
        mock_entry.title = "Valid Post"
        mock_entry.get = lambda k, d=None: getattr(mock_entry, k, d)

        mock_feed = MagicMock()
        mock_feed.entries = [mock_entry]
        mock_parse.return_value = mock_feed

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"<html><body><div class='post-content'>Valid Content</div></body></html>"
        mock_get.return_value = mock_response

        with patch('socket.gethostbyname') as mock_socket:
            mock_socket.return_value = "93.184.216.34"
            posts = extract_substack_content("https://valid-site.com")

        mock_get.assert_called_once()
        self.assertEqual(len(posts), 1)

if __name__ == '__main__':
    unittest.main()
