import unittest
from unittest.mock import patch, MagicMock
from handler import handler, MAX_POSTS_PER_NEWSLETTER, MAX_NEWSLETTERS

class TestHandlerDoS(unittest.TestCase):
    @patch('handler.extract_substack_content')
    @patch('handler.analyze_research_intelligence')
    def test_large_posts_per_newsletter(self, mock_analyze, mock_extract):
        # Mock dependencies
        mock_extract.return_value = []
        mock_analyze.return_value = {}

        # Input with excessive posts_per_newsletter
        event = {
            'input': {
                'newsletters': ['https://example.com'],
                'posts_per_newsletter': 1000
            }
        }

        result = handler(event)

        # Verify that it returns an error instead of silently capping
        self.assertIn("error", result)
        self.assertIn(f"Max allowed: {MAX_POSTS_PER_NEWSLETTER}", result["error"])
        mock_extract.assert_not_called()

    @patch('handler.extract_substack_content')
    @patch('handler.analyze_research_intelligence')
    def test_too_many_newsletters(self, mock_analyze, mock_extract):
        mock_extract.return_value = []
        mock_analyze.return_value = {}

        # Input with excessive newsletters
        many_newsletters = [f'https://example.com/{i}' for i in range(100)]
        event = {
            'input': {
                'newsletters': many_newsletters,
                'posts_per_newsletter': 1
            }
        }

        result = handler(event)

        # Verify it returns an error
        self.assertIn("error", result)
        self.assertIn(f"Max allowed: {MAX_NEWSLETTERS}", result["error"])
        mock_extract.assert_not_called()

if __name__ == '__main__':
    unittest.main()
