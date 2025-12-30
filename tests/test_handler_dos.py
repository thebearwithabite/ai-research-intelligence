import unittest
from unittest.mock import patch, MagicMock
from handler import handler

class TestHandlerDoS(unittest.TestCase):
    @patch('handler.extract_substack_content')
    @patch('handler.analyze_research_intelligence')
    def test_input_limits_newsletters(self, mock_analyze, mock_extract):
        mock_extract.return_value = []
        mock_analyze.return_value = {}

        # huge list of newsletters
        newsletters = ["http://example.com"] * 100
        job_input = {
            "input": {
                "newsletters": newsletters,
                "posts_per_newsletter": 100
            }
        }

        handler(job_input)

        # Check that we didn't call extract 100 times
        # We expect it to be capped (at 10)
        self.assertLessEqual(mock_extract.call_count, 10)

        # Check that the second arg (max_posts) was capped
        if mock_extract.called:
            args, _ = mock_extract.call_args
            # args[0] is newsletter_url, args[1] is max_posts
            self.assertLessEqual(args[1], 5)

if __name__ == '__main__':
    unittest.main()
