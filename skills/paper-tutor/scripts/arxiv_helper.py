#!/usr/bin/env python3
"""
Helper script for fetching paper metadata from arXiv.

Usage:
    python arxiv_helper.py --id 2301.07041
    python arxiv_helper.py --title "Attention Is All You Need"
    python arxiv_helper.py --url https://arxiv.org/abs/2301.07041
"""

import argparse
import sys
import re
from urllib.parse import urlparse

try:
    import arxiv
except ImportError:
    print("Error: arxiv library not installed. Install with: pip install arxiv")
    sys.exit(1)


def extract_arxiv_id(input_str):
    """Extract arXiv ID from various input formats."""
    # Already looks like an ID
    if re.match(r'^\d{4}\.\d{4,5}(v\d+)?$', input_str):
        return input_str

    # URL format
    if input_str.startswith('http'):
        path = urlparse(input_str).path
        # Extract ID from path like /abs/2301.07041 or /pdf/2301.07041.pdf
        match = re.search(r'(\d{4}\.\d{4,5})(v\d+)?', path)
        if match:
            return match.group(1)

    return None


def fetch_by_id(arxiv_id):
    """Fetch paper metadata by arXiv ID."""
    try:
        search = arxiv.Search(id_list=[arxiv_id])
        paper = next(arxiv.Client().results(search))

        return {
            'id': arxiv_id,
            'title': paper.title,
            'authors': [a.name for a in paper.authors],
            'summary': paper.summary.replace('\n', ' '),
            'published': paper.published.strftime('%Y-%m-%d'),
            'categories': paper.categories,
            'pdf_url': paper.pdf_url,
            'primary_category': paper.primary_category
        }
    except Exception as e:
        return {'error': str(e)}


def fetch_by_title(title_query):
    """Search for paper by title."""
    try:
        search = arxiv.Search(
            query=f'ti:"{title_query}"',
            max_results=1,
            sort_by=arxiv.SortCriterion.Relevance
        )
        result = next(arxiv.Client().results(search), None)

        if not result:
            return {'error': f'No paper found with title: {title_query}'}

        return {
            'id': result.entry_id.split('/')[-1],
            'title': result.title,
            'authors': [a.name for a in result.authors],
            'summary': result.summary.replace('\n', ' '),
            'published': result.published.strftime('%Y-%m-%d'),
            'categories': result.categories,
            'pdf_url': result.pdf_url,
            'primary_category': result.primary_category
        }
    except Exception as e:
        return {'error': str(e)}


def format_output(paper_data):
    """Format paper data for display."""
    if 'error' in paper_data:
        return f"Error: {paper_data['error']}"

    output = f"""
{'='*60}
Paper Metadata
{'='*60}

Title: {paper_data['title']}
arXiv ID: {paper_data['id']}
Published: {paper_data['published']}
Categories: {', '.join(paper_data['categories'])}
Primary: {paper_data['primary_category']}

Authors:
{', '.join(paper_data['authors'][:5])}
{f"... and {len(paper_data['authors']) - 5} more" if len(paper_data['authors']) > 5 else ""}

Abstract:
{paper_data['summary'][:500]}{'...' if len(paper_data['summary']) > 500 else ''}

PDF: {paper_data['pdf_url']}
{'='*60}
"""
    return output


def main():
    parser = argparse.ArgumentParser(description='Fetch paper metadata from arXiv')
    parser.add_argument('--id', help='arXiv ID (e.g., 2301.07041)')
    parser.add_argument('--title', help='Paper title to search')
    parser.add_argument('--url', help='arXiv URL')
    parser.add_argument('--json', action='store_true', help='Output as JSON')

    args = parser.parse_args()

    # Determine input type
    if args.id:
        arxiv_id = extract_arxiv_id(args.id)
        if not arxiv_id:
            arxiv_id = args.id  # Use as-is
        paper_data = fetch_by_id(arxiv_id)
    elif args.url:
        arxiv_id = extract_arxiv_id(args.url)
        if not arxiv_id:
            print("Error: Could not extract arXiv ID from URL")
            sys.exit(1)
        paper_data = fetch_by_id(arxiv_id)
    elif args.title:
        paper_data = fetch_by_title(args.title)
    else:
        parser.print_help()
        sys.exit(1)

    if args.json:
        import json
        print(json.dumps(paper_data, indent=2, default=str))
    else:
        print(format_output(paper_data))


if __name__ == '__main__':
    main()
