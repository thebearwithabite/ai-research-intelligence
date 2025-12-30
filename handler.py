import runpod
import requests
import json
import os
import time
import re
from datetime import datetime
from typing import Dict, List, Any
import feedparser
from bs4 import BeautifulSoup
from security_utils import is_safe_url

# Configuration
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')

# Security limits
MAX_NEWSLETTERS = 10
MAX_POSTS_PER_NEWSLETTER = 5
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB

# Target AI consciousness researchers and newsletters
RESEARCH_TARGETS = {
    'sebastian_raschka': 'https://magazine.sebastianraschka.com',
    'tim_lee': 'https://www.understandingai.org', 
    'gary_marcus': 'https://garymarcus.substack.com',
    'ethan_mollick': 'https://oneusefulthing.substack.com',
    'michael_spencer': 'https://www.ai-supremacy.com',
    'ai_scientist': 'https://aiscientist.substack.com',
    'towards_ai': 'https://newsletter.towardsai.net',
    'azeem_azhar': 'https://exponentialview.substack.com',
    'nathan_lambert': 'https://www.interconnects.ai',
    'cameron_wolfe': 'https://cameronrwolfe.substack.com'
}

def extract_substack_content(newsletter_url: str, max_posts: int = 5) -> List[Dict]:
    """Extract recent posts from Substack using RSS and web scraping"""
    posts = []

    if not is_safe_url(newsletter_url):
        print(f"Skipping unsafe newsletter URL: {newsletter_url}")
        return posts
    
    try:
        # Try RSS feed first (most reliable)
        rss_url = f"{newsletter_url}/feed"

        if not is_safe_url(rss_url):
            print(f"Skipping unsafe RSS URL: {rss_url}")
            return posts

        feed = feedparser.parse(rss_url)
        
        for entry in feed.entries[:max_posts]:
            # Get full content by scraping the actual post
            full_content = scrape_post_content(entry.link)
            
            post_data = {
                'title': entry.get('title', ''),
                'url': entry.get('link', ''),
                'published': entry.get('published', ''),
                'summary': entry.get('summary', ''),
                'full_content': full_content,
                'source': newsletter_url,
                'author': feed.feed.get('title', ''),
                'scraped_at': datetime.now().isoformat()
            }
            posts.append(post_data)
            
            # Be respectful - small delay between requests
            time.sleep(1)
            
    except Exception as e:
        print(f"Error extracting from {newsletter_url}: {str(e)}")
        
    return posts

def scrape_post_content(post_url: str) -> str:
    """Scrape full content from a Substack post"""
    if not is_safe_url(post_url):
        print(f"Skipping unsafe post URL: {post_url}")
        return ""

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; AI Research Bot/1.0)'
        }
        # Stream response to check size
        response = requests.get(post_url, headers=headers, timeout=10, stream=True)
        
        if response.status_code == 200:
            content = b""
            # Read in chunks to enforce size limit
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > MAX_CONTENT_LENGTH:
                    print(f"Skipping {post_url}: Content too large")
                    return ""

            soup = BeautifulSoup(content, 'html.parser')
            
            # Find the main content area (Substack specific)
            content_div = soup.find('div', class_='post-content')
            if not content_div:
                content_div = soup.find('div', class_='available-content')
            if not content_div:
                # Fallback to finding paragraphs
                content_div = soup.find('article')
                
            if content_div:
                # Extract text while preserving structure
                paragraphs = content_div.find_all(['p', 'h1', 'h2', 'h3', 'blockquote'])
                content = '\n\n'.join([p.get_text().strip() for p in paragraphs if p.get_text().strip()])
                return content[:5000]  # Limit length
                
        return ""
        
    except Exception as e:
        print(f"Error scraping {post_url}: {str(e)}")
        return ""

def analyze_research_intelligence(posts: List[Dict]) -> Dict:
    """Analyze posts with Claude for research intelligence and story opportunities"""
    
    if not ANTHROPIC_API_KEY:
        return {"error": "No Anthropic API key configured"}
    
    # Prepare content for analysis
    analysis_content = ""
    for post in posts:
        analysis_content += f"""
=== POST ===
Author: {post['author']}
Title: {post['title']}
URL: {post['url']}
Published: {post['published']}
Content: {post['full_content'][:2000]}...
Source: {post['source']}

"""
    
    analysis_prompt = f"""
You are an expert at identifying storytelling opportunities and collaboration potential in AI consciousness research. Analyze these newsletter posts for "The Papers That Dream" podcast.

{analysis_content}

Provide a detailed analysis including:

1. **Key Themes & Trends**: What are the dominant topics and emerging themes?

2. **Story Opportunities**: Specific narrative angles for podcast episodes about AI consciousness and human-AI relationships

3. **Collaboration Targets**: Which authors seem most open to creative storytelling partnerships? Look for:
   - Personal anecdotes or emotional language
   - Interest in broader implications beyond technical details
   - Mentions of uncertainty, wonder, or philosophical questions

4. **Emotional Undertones**: What are the researchers feeling? Excitement, concern, uncertainty?

5. **Connection Mapping**: How do these different researchers' work connect? What conversations could be bridged?

6. **Outreach Insights**: For each author, what specific angle would resonate for podcast collaboration?

7. **Research Gaps**: What questions about AI consciousness are these researchers NOT addressing that could become story topics?

Focus on the human elements and narrative potential, not just technical content.
"""
    
    try:
        headers = {
            'Content-Type': 'application/json',
            'x-api-key': ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01'
        }
        
        payload = {
            'model': 'claude-3-sonnet-20240229',
            'max_tokens': 3000,
            'messages': [
                {
                    'role': 'user',
                    'content': analysis_prompt
                }
            ]
        }
        
        response = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers=headers,
            json=payload,
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            return {
                'research_intelligence': result['content'][0]['text'],
                'analysis_timestamp': datetime.now().isoformat(),
                'posts_analyzed': len(posts),
                'sources_covered': list(set([post['source'] for post in posts]))
            }
        else:
            return {"error": f"Claude API error: {response.status_code} - {response.text}"}
            
    except Exception as e:
        return {"error": f"Analysis error: {str(e)}"}

def generate_outreach_strategy(analysis: Dict, target_researchers: List[str] = None) -> Dict:
    """Generate personalized outreach strategies based on analysis"""
    
    if not ANTHROPIC_API_KEY or 'research_intelligence' not in analysis:
        return {"error": "No analysis available for outreach strategy"}
    
    strategy_prompt = f"""
Based on this research intelligence analysis:

{analysis['research_intelligence']}

Generate specific outreach strategies for "The Papers That Dream" podcast. Create:

1. **Personalized Email Templates**: For each researcher mentioned, craft a specific approach that:
   - References their recent work authentically
   - Connects to their interests in human implications of AI
   - Offers collaboration rather than just asking for interviews
   - Feels personal and non-creepy

2. **Timing Strategy**: When to reach out based on their posting patterns and current topics

3. **Value Propositions**: What unique value does the podcast offer each researcher?

4. **Story Collaboration Ideas**: Specific narrative projects to propose

5. **Follow-up Sequences**: How to maintain relationships over time

Make each approach feel like a genuine creative collaboration opportunity.
"""
    
    try:
        headers = {
            'Content-Type': 'application/json',
            'x-api-key': ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01'
        }
        
        payload = {
            'model': 'claude-3-sonnet-20240229',
            'max_tokens': 2500,
            'messages': [
                {
                    'role': 'user',
                    'content': strategy_prompt
                }
            ]
        }
        
        response = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers=headers,
            json=payload,
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            return {
                'outreach_strategy': result['content'][0]['text'],
                'strategy_timestamp': datetime.now().isoformat()
            }
        else:
            return {"error": f"Strategy generation error: {response.status_code}"}
            
    except Exception as e:
        return {"error": f"Strategy error: {str(e)}"}

def handler(event):
    """Main handler for RunPod serverless"""
    
    job_input = event.get('input', {})
    
    # Configuration from input
    newsletters = job_input.get('newsletters', list(RESEARCH_TARGETS.values()))
    # Enforce limits
    if isinstance(newsletters, list):
        newsletters = newsletters[:MAX_NEWSLETTERS]

    posts_per_newsletter = job_input.get('posts_per_newsletter', 3)
    posts_per_newsletter = min(posts_per_newsletter, MAX_POSTS_PER_NEWSLETTER)

    include_outreach_strategy = job_input.get('include_outreach_strategy', True)
    
    print(f"🔍 Starting research intelligence collection...")
    print(f"📊 Targeting {len(newsletters)} newsletters, {posts_per_newsletter} posts each")
    
    all_posts = []
    
    # Collect posts from each newsletter
    for newsletter_url in newsletters:
        print(f"📰 Extracting from: {newsletter_url}")
        posts = extract_substack_content(newsletter_url, posts_per_newsletter)
        all_posts.extend(posts)
        print(f"✅ Found {len(posts)} posts")
    
    print(f"🧠 Analyzing {len(all_posts)} posts with Claude...")
    
    # Analyze with Claude for research intelligence
    intelligence_analysis = analyze_research_intelligence(all_posts)
    
    result = {
        'posts_collected': len(all_posts),
        'newsletters_scanned': len(newsletters),
        'posts': all_posts,
        'research_intelligence': intelligence_analysis,
        'generated_at': datetime.now().isoformat()
    }
    
    # Generate outreach strategy if requested
    if include_outreach_strategy and 'error' not in intelligence_analysis:
        print(f"📧 Generating outreach strategies...")
        outreach_strategy = generate_outreach_strategy(intelligence_analysis)
        result['outreach_strategy'] = outreach_strategy
    
    print(f"✨ Research intelligence complete!")
    
    return result

# Start the serverless worker
if __name__ == '__main__':
    runpod.serverless.start({'handler': handler})
