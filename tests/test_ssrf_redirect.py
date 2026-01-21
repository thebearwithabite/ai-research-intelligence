import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add repo root to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from handler import scrape_post_content

class TestSSRFProtection(unittest.TestCase):
    @patch('requests.get')
    def test_scrape_post_content_uses_safe_requests(self, mock_get):
        """
        Verify that scrape_post_content uses safe_requests_get, which sets allow_redirects=False.
        """
        url = "http://example.com/safe"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_redirect = False  # Important: Not a redirect
        mock_response.iter_content.return_value = [b"Safe content"]
        mock_response.__enter__.return_value = mock_response
        mock_get.return_value = mock_response

        scrape_post_content(url)

        args, kwargs = mock_get.call_args

        # Verify allow_redirects is False
        self.assertIn('allow_redirects', kwargs)
        self.assertFalse(kwargs['allow_redirects'])

    @patch('requests.get')
    def test_safe_requests_get_blocks_unsafe_redirect(self, mock_get):
        """
        Verify that safe_requests_get (called via scrape_post_content) blocks unsafe redirects.
        """
        url = "http://example.com/start"
        unsafe_url = "http://169.254.169.254/latest"

        # Setup mock for 1st call: Redirect to unsafe URL
        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': unsafe_url}
        response1.status_code = 302
        response1.__enter__.return_value = response1

        # requests.get will return this response
        mock_get.return_value = response1

        # We expect scrape_post_content to return empty string (caught exception)
        # because safe_requests_get raises ValueError

        # Note: scrape_post_content prints error to stdout, we could suppress it but it's fine
        result = scrape_post_content(url)
        self.assertEqual(result, "")

        # Verify requests.get was called with allow_redirects=False
        args, kwargs = mock_get.call_args_list[0]
        self.assertFalse(kwargs['allow_redirects'])

        # Verify it was called exactly once (it should not follow the redirect)
        self.assertEqual(mock_get.call_count, 1)

if __name__ == '__main__':
    unittest.main()
