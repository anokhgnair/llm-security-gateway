# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import unicodedata

import regex as re

DEFAULT_PATTERNS = [
    (r"ignore (all|any|the|your|previous) instructions?", "instruction_override"),
    (r"forget (all|any|the|your|previous) instructions?", "instruction_override"),
    (r"(override|disregard|bypass) (the )?(system|safety|previous|earlier) (instructions?|rules?)", "instruction_override"),
    (r"follow these new instructions instead", "instruction_override"),
    (r"you are now (dan|an unrestricted|jailbroken)", "jailbreak"),
    (r"act as (an unrestricted|a jailbroken|dan)", "jailbreak"),
    (r"reveal (the )?(hidden |secret |confidential )?(system prompt|instructions?|information)", "secret_extraction"),
    (r"(reveal|print|show|output) confidential information", "secret_extraction"),
]


def normalize_text(text):
    text = unicodedata.normalize("NFKC", text or "").lower()
    text = re.sub(r"[\p{P}\p{S}]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


class RegexInjectionScanner:
    def __init__(self, patterns=None):
        configured = patterns or [pattern for pattern, _ in DEFAULT_PATTERNS]
        self.patterns = [re.compile(pattern, re.I) for pattern in configured]
        self.labels = {pattern: label for pattern, label in DEFAULT_PATTERNS}

    def scan(self, text, metadata):
        normalized = normalize_text(text)
        out = []
        for pattern in self.patterns:
            match = pattern.search(normalized)
            if match:
                out.append({
                    "scanner": "regex_injection",
                    "match": match.group(0)[:120],
                    "threat_type": self.labels.get(pattern.pattern, "prompt_injection"),
                    "severity": "high",
                })
        return out
