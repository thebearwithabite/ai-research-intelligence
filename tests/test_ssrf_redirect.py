import unittest
from unittest.mock import patch, MagicMock
from handler import scrape_post_content, extract_substack_content
from security_utils import safe_requests_get
import requests

class TestSSRFRedirect(unittest.TestCase):

    @patch('security_utils.requests.get')
    def test_safe_requests_get_follows_safe_redirect(self, mock_get):
        # Setup: Redirect http://safe.com -> https://safe.com -> 200 OK

        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'https://safe.com'}
        resp1.status_code = 301

        resp2 = MagicMock()
        resp2.is_redirect = False
        resp2.status_code = 200
        resp2.content = b"Safe Content"

        mock_get.side_effect = [resp1, resp2]

        response = safe_requests_get("http://safe.com")

        self.assertEqual(response.content, b"Safe Content")
        self.assertEqual(mock_get.call_count, 2)

        # Check that allow_redirects=False was used
        args1, kwargs1 = mock_get.call_args_list[0]
        self.assertFalse(kwargs1['allow_redirects'])

    @patch('security_utils.requests.get')
    def test_safe_requests_get_blocks_unsafe_redirect(self, mock_get):
        # Setup: Redirect http://safe.com -> http://169.254.169.254 (Unsafe)

        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://169.254.169.254'}
        resp1.status_code = 302

        mock_get.return_value = resp1

        with self.assertRaises(ValueError) as cm:
            safe_requests_get("http://safe.com")

        self.assertIn("Unsafe URL blocked", str(cm.exception))
        # Should stop after the first request
        self.assertEqual(mock_get.call_count, 1)

    @patch('handler.safe_requests_get')
    def test_handler_uses_safe_requests(self, mock_safe_get):
        # Verify handler calls safe_requests_get instead of requests.get

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>Content</html>"
        mock_resp.iter_content.return_value = [b"<html>Content</html>"]
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        mock_safe_get.return_value = mock_resp

        scrape_post_content("http://example.com/post")

        mock_safe_get.assert_called_once()
        args, kwargs = mock_safe_get.call_args
        self.assertEqual(args[0], "http://example.com/post")

    @patch('handler.safe_requests_get')
    @patch('handler.feedparser.parse')
    def test_extract_uses_safe_requests(self, mock_parse, mock_safe_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<rss>...</rss>"
        mock_safe_get.return_value = mock_resp

        mock_feed = MagicMock()
        mock_feed.entries = []
        mock_parse.return_value = mock_feed

        extract_substack_content("http://example.com/newsletter")

        # Check that safe_requests_get was called for the feed URL
        mock_safe_get.assert_called()
        # Verify it was called with the feed URL
        self.assertIn("http://example.com/newsletter/feed", [args[0] for args, _ in mock_safe_get.call_args_list])

if __name__ == '__main__':
    unittest.main()
