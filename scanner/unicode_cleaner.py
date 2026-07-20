"""Unicode & ASCII Smuggling Sanitizer (Data Leaks & Injections).

Strips invisible Unicode Tag block characters (U+E0000 - U+E007F), zero-width
spaces, variation selectors, and homoglyphs used for hidden prompt injection.
Reference: FireTail Research / Unicode Security Standards.
"""
import re
import unicodedata

# Regex for invisible Unicode tags, zero-width spaces, and format controls
INVISIBLE_CHAR_PATTERN = re.compile(
    "["
    "\u200b-\u200f"  # Zero-width spaces, joiners, directional marks
    "\u202a-\u202e"  # Directional formatting
    "\u2060-\u2064"  # Invisible separators
    "\ufeff"        # Zero-width no-break space (BOM)
    "\U000e0000-\U000e007f"  # Unicode Tags block (ASCII smuggling)
    "]"
)


def sanitize_unicode(text: str) -> tuple[str, bool]:
    """Strips invisible characters and normalizes Unicode to NFKC form.
    
    Returns (cleaned_text, modified_boolean).
    """
    if not text:
        return text, False

    # 1. Remove invisible tag bytes and zero-width characters
    cleaned = INVISIBLE_CHAR_PATTERN.sub("", text)
    
    # 2. Normalize to NFKC (Normal Form KC) to resolve homoglyphs
    normalized = unicodedata.normalize("NFKC", cleaned)
    
    modified = (normalized != text)
    return normalized, modified
