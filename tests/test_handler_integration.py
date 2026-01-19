import unittest
from unittest.mock import patch, MagicMock
from handler import extract_substack_content, scrape_post_content

class TestHandlerIntegration(unittest.TestCase):
    @patch('handler.safe_requests_get')
    @patch('handler.feedparser.parse')
    def test_extract_substack_content_uses_safe_get(self, mock_parse, mock_safe_get):
        # Setup
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"rss content"
        mock_safe_get.return_value = mock_resp

        # Mock feedparser return
        mock_feed = MagicMock()
        mock_feed.entries = []
        mock_feed.feed.get.return_value = "Author"
        mock_parse.return_value = mock_feed

        # Execute
        extract_substack_content("http://example.com", 1)

        # Verify
        mock_safe_get.assert_called_with("http://example.com/feed", timeout=10)
        mock_parse.assert_called_with(b"rss content")

    @patch('handler.safe_requests_get')
    def test_scrape_post_content_uses_safe_get(self, mock_safe_get):
        # Setup
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # iter_content for DoS protection loop
        mock_resp.iter_content.return_value = [b"<html><body>content</body></html>"]
        # Context manager support
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        mock_safe_get.return_value = mock_resp

        # Execute
        scrape_post_content("http://example.com/post")

        # Verify
        mock_safe_get.assert_called()
        args, kwargs = mock_safe_get.call_args
        self.assertEqual(args[0], "http://example.com/post")
        self.assertEqual(kwargs['stream'], True)

if __name__ == '__main__':
    unittest.main()
