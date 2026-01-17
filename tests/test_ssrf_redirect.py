import unittest
from unittest.mock import patch, MagicMock
import requests
import feedparser
from handler import scrape_post_content, extract_substack_content
from security_utils import is_safe_url

class TestSSRFRedirect(unittest.TestCase):
    @patch('requests.get')
    def test_scrape_post_content_uses_safe_requests_get(self, mock_get):
        """
        Verify that scrape_post_content now uses safe_requests_get mechanism,
        which means it should call requests.get with allow_redirects=False.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_content.return_value = [b"<html><body>Safe data</body></html>"]
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        mock_response.is_redirect = False

        mock_get.return_value = mock_response

        url = "http://example.com/safe"
        scrape_post_content(url)

        # Verify requests.get was called
        self.assertTrue(mock_get.called)

        # Verify that allow_redirects was set to False
        args, kwargs = mock_get.call_args
        self.assertEqual(kwargs.get('allow_redirects'), False, "Security Fix: requests.get should handle redirects manually (allow_redirects=False)")

    @patch('requests.get')
    @patch('feedparser.parse')
    def test_extract_substack_content_fetches_content_first(self, mock_parse, mock_get):
        """
        Verify that extract_substack_content fetches content using safe_requests_get
        before passing it to feedparser.
        """
        # Mock successful request
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"<rss>...</rss>"
        mock_response.is_redirect = False
        mock_get.return_value = mock_response

        url = "http://example.com/feed"
        extract_substack_content(url)

        # Verify requests.get was called to fetch the feed (implied safe_requests_get)
        # Note: safe_requests_get calls requests.get
        self.assertTrue(mock_get.called)

        # Verify feedparser.parse was called with the CONTENT (bytes), not the URL
        mock_parse.assert_called_with(b"<rss>...</rss>")

if __name__ == '__main__':
    unittest.main()
