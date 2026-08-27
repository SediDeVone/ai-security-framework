"""Improper Output Sanitizer & Validator (Output Handling Defense).

Sanitizes model-generated output (HTML, Markdown, SQL queries, URLs) to prevent
Stored XSS, SSRF, SQL Injection, or Remote Code Execution (RCE) via untrusted LLM outputs.
Reference: OWASP Top 10 for LLM (LLM05).
"""
import html
import re
from typing import Dict, Any, List


def sanitize_html(text: str) -> str:
    """Sanitizes HTML tags and attributes using parser-based nh3 (fallback to html.escape)."""
    if not text:
        return text
        
    try:
        import nh3
        return nh3.clean(text)
    except ImportError:
        # Fallback to strict HTML escaping if nh3 is not available, avoiding fragile regex XSS bypasses
        return html.escape(text)



def validate_generated_url(url: str, allowed_domains: List[str] = None) -> bool:
    """Validates model-generated URLs to prevent SSRF or exfiltration endpoints."""
    if not url.startswith(("http://", "https://")):
        return False
        
    # Check against localhost / internal IP SSRF attempts
    if re.search(r"://(127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))", url):
        return False
        
    if allowed_domains:
        domain_match = re.search(r"://([^/:]+)", url)
        if domain_match:
            domain = domain_match.group(1).lower()
            return any(domain == d or domain.endswith("." + d) for d in allowed_domains)
            
    return True
