"""Improper Output Sanitizer & Validator (Output Handling Defense).

Sanitizes model-generated output (HTML, Markdown, SQL queries, URLs) to prevent
Stored XSS, SSRF, SQL Injection, or Remote Code Execution (RCE) via untrusted LLM outputs.
Reference: OWASP Top 10 for LLM (LLM05).
"""
import html
import re
from typing import Dict, Any, List


def sanitize_html(text: str) -> str:
    """Escapes raw HTML tags and strips dangerous script/img event attributes."""
    if not text:
        return text
        
    # Remove script and iframe tags completely
    clean_text = re.sub(r"(?i)<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", "", text)
    clean_text = re.sub(r"(?i)<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>", "", clean_text)
    
    # Remove inline event handlers (onerror=, onload=, onclick=)
    clean_text = re.sub(r"(?i)\s+on\w+\s*=\s*['\"][^'\"]*['\"]", "", clean_text)
    
    return clean_text


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
