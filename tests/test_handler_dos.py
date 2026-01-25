import unittest
from unittest.mock import patch, MagicMock
from handler import handler, MAX_NEWSLETTERS, MAX_POSTS_PER_NEWSLETTER

class TestHandlerDoS(unittest.TestCase):
    @patch('handler.extract_substack_content')
    @patch('handler.analyze_research_intelligence')
    def test_handler_newsletters_limit(self, mock_analyze, mock_extract):
        # Setup mocks
        mock_extract.return_value = []
        mock_analyze.return_value = {}

        # 1. Too many newsletters
        many_newsletters = [f"http://example.com/{i}" for i in range(MAX_NEWSLETTERS + 1)]
        event = {
            'input': {
                'newsletters': many_newsletters,
                'posts_per_newsletter': 1
            }
        }

        result = handler(event)

        # Expect success (silent truncation)
        self.assertIsInstance(result, dict)
        self.assertNotIn("error", result)

        # Verify processing happened for MAX_NEWSLETTERS
        self.assertEqual(mock_extract.call_count, MAX_NEWSLETTERS)

    @patch('handler.extract_substack_content')
    @patch('handler.analyze_research_intelligence')
    def test_handler_posts_limit(self, mock_analyze, mock_extract):
        # Setup mocks
        mock_extract.return_value = []
        mock_analyze.return_value = {}

        # 2. Too many posts per newsletter
        event = {
            'input': {
                'newsletters': ['http://example.com/1'],
                'posts_per_newsletter': MAX_POSTS_PER_NEWSLETTER + 1
            }
        }

        result = handler(event)

        # Expect success (silent capping)
        self.assertIsInstance(result, dict)
        self.assertNotIn("error", result)

        # Verify processing happened
        mock_extract.assert_called_once()
        # Check that the call argument used MAX_POSTS_PER_NEWSLETTER
        args, _ = mock_extract.call_args
        self.assertEqual(args[1], MAX_POSTS_PER_NEWSLETTER)

    @patch('handler.extract_substack_content')
    @patch('handler.analyze_research_intelligence')
    def test_handler_valid_input(self, mock_analyze, mock_extract):
        # Setup mocks
        mock_extract.return_value = [{'title': 'test'}]
        mock_analyze.return_value = {'research_intelligence': 'analysis'}

        # 3. Valid input
        event = {
            'input': {
                'newsletters': ['http://example.com/1'],
                'posts_per_newsletter': MAX_POSTS_PER_NEWSLETTER
            }
        }

        result = handler(event)

        # Expect success
        self.assertNotIn("error", result)
        self.assertEqual(result['posts_collected'], 1)
        mock_extract.assert_called_once()

if __name__ == '__main__':
    unittest.main()
