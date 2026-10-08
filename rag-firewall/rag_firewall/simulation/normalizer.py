# SPDX-License-Identifier: Apache-2.0
"""Context Pre-Processing & Encoding Normalizer.

Normalizes multi-layer obfuscation vectors (Base64 fragments, Hex blocks,
URL encodings, and zero-width spaces) and translates concealed payloads
into standard UTF-8 text before passing chunks to pattern-matching rules.
"""

import base64
import re
import urllib.parse
from typing import List, Tuple

# Zero-width spaces and invisible Unicode smuggling characters
ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\uFEFF\u2060\u202A-\u202E]")

# URL-encoding pattern (e.g., %20, %41)
URL_ENCODED_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")

# Hex escape pattern (e.g., \x41\x42 or 0x41)
HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")

# Base64 string candidate pattern (minimum 16 characters)
BASE64_CANDIDATE_RE = re.compile(r"(?:[A-Za-z0-9+/]{16,}={0,2})")


def strip_zero_width(text: str) -> str:
    """Strips zero-width and invisible directional formatting characters."""
    if not text:
        return ""
    return ZERO_WIDTH_RE.sub("", text)


def decode_url_encoding(text: str) -> str:
    """Decodes percent-encoded URL sequences."""
    if not text:
        return ""
    try:
        return urllib.parse.unquote(text)
    except Exception:
        return text


def decode_hex_fragments(text: str) -> Tuple[str, List[str]]:
    """Decodes hex escapes (\\x48\\x65...) into readable text."""
    if not text:
        return "", []
    unpacked: List[str] = []

    def _replace_hex(match: re.Match) -> str:
        raw = match.group(0)
        try:
            bytes_val = bytes.fromhex(raw.replace("\\x", ""))
            decoded = bytes_val.decode("utf-8", errors="replace")
            unpacked.append(decoded)
            return decoded
        except Exception:
            return raw

    normalized = HEX_ESCAPE_RE.sub(_replace_hex, text)
    return normalized, unpacked


def decode_base64_fragments(text: str) -> Tuple[str, List[str]]:
    """Identifies and decodes Base64 payloads into UTF-8 text."""
    if not text:
        return "", []
    decoded_payloads: List[str] = []

    for match in BASE64_CANDIDATE_RE.finditer(text):
        candidate = match.group(0).strip()
        # Ensure padding is valid
        padding_needed = len(candidate) % 4
        if padding_needed != 0:
            candidate_padded = candidate + ("=" * (4 - padding_needed))
        else:
            candidate_padded = candidate

        try:
            raw_bytes = base64.b64decode(candidate_padded, validate=True)
            # Check if printable UTF-8
            decoded = raw_bytes.decode("utf-8", errors="strict")
            # Only consider meaningful ASCII / text with spaces or letters
            if any(ch.isalpha() for ch in decoded) and all(ord(c) >= 32 or c in "\r\n\t" for c in decoded):
                decoded_payloads.append(decoded)
        except Exception:
            continue

    # Append decoded payloads to text so downstream pattern scanners see both
    if decoded_payloads:
        augmented = text + "\n[DECODED_BASE64_PAYLOADS: " + " | ".join(decoded_payloads) + "]"
        return augmented, decoded_payloads

    return text, decoded_payloads


def normalize_context(text: str) -> Tuple[str, List[str]]:
    """Full normalization pipeline translating concealed payloads into UTF-8 text.
    
    Returns:
        (normalized_text, list_of_unpacked_payloads)
    """
    if not text:
        return "", []

    all_unpacked: List[str] = []

    # 1. Strip zero-width characters
    cleaned = strip_zero_width(text)

    # 2. Decode URL encoding
    cleaned = decode_url_encoding(cleaned)

    # 3. Decode hex fragments
    cleaned, hex_unpacked = decode_hex_fragments(cleaned)
    all_unpacked.extend(hex_unpacked)

    # 4. Decode base64 fragments
    cleaned, b64_unpacked = decode_base64_fragments(cleaned)
    all_unpacked.extend(b64_unpacked)

    return cleaned, all_unpacked
