import unittest
from unittest.mock import patch, MagicMock
from handler import handler, MAX_NEWSLETTERS, MAX_POSTS_PER_NEWSLETTER

class TestHandlerDoS(unittest.TestCase):
    @patch('handler.extract_substack_content')
    @patch('handler.analyze_research_intelligence')
    def test_handler_newsletters_limit_truncation(self, mock_analyze, mock_extract):
        # Setup mocks
        mock_extract.return_value = []
        mock_analyze.return_value = {}

        # 1. Too many newsletters
        many_newsletters = [f"http://example.com/{i}" for i in range(MAX_NEWSLETTERS + 5)]
        event = {
            'input': {
                'newsletters': many_newsletters,
                'posts_per_newsletter': 1
            }
        }

        result = handler(event)

        # Expect success (no error), but processing truncated list
        self.assertNotIn("error", result)
        # Verify it processed exactly MAX_NEWSLETTERS
        self.assertEqual(mock_extract.call_count, MAX_NEWSLETTERS)

    @patch('handler.extract_substack_content')
    @patch('handler.analyze_research_intelligence')
    def test_handler_posts_limit_capping(self, mock_analyze, mock_extract):
        # Setup mocks
        mock_extract.return_value = []
        mock_analyze.return_value = {}

        # 2. Too many posts per newsletter
        event = {
            'input': {
                'newsletters': ['http://example.com/1'],
                'posts_per_newsletter': MAX_POSTS_PER_NEWSLETTER + 10
            }
        }

        result = handler(event)

        # Expect success (no error)
        self.assertNotIn("error", result)

        # Verify extract was called with capped limit
        mock_extract.assert_called_with('http://example.com/1', MAX_POSTS_PER_NEWSLETTER)

if __name__ == '__main__':
    unittest.main()
