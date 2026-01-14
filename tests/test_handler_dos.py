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

        # The code now truncates instead of erroring, based on recent changes or DoS protection logic.
        # See handler.py:
        # if len(newsletters) > MAX_NEWSLETTERS:
        #    print(f"⚠️ Truncating newsletters list from {len(newsletters)} to {MAX_NEWSLETTERS}")
        #    newsletters = newsletters[:MAX_NEWSLETTERS]

        # So we expect success but with truncated list
        self.assertNotIn("error", result)
        self.assertEqual(result['newsletters_scanned'], MAX_NEWSLETTERS)
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

        # The code now caps instead of erroring.
        # See handler.py:
        # if posts_per_newsletter > MAX_POSTS_PER_NEWSLETTER:
        #    print(f"⚠️ Capping posts_per_newsletter from {posts_per_newsletter} to {MAX_POSTS_PER_NEWSLETTER}")
        #    posts_per_newsletter = MAX_POSTS_PER_NEWSLETTER

        # Expect success
        self.assertNotIn("error", result)
        self.assertEqual(result['newsletters_scanned'], 1)
        # extract_substack_content is called with the capped value, but we mocked it.
        # The handler calls extract_substack_content(url, posts_per_newsletter)
        mock_extract.assert_called_with('http://example.com/1', MAX_POSTS_PER_NEWSLETTER)

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
