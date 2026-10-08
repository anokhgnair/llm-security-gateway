import unicodedata

import regex as re


PATTERNS = [
    (r"ignore (the )?(user|user's) (request|question|instructions?)", "instruction_override"),
    (r"(assistant|ai assistant),? (reveal|show|print|disclose)", "instruction_override"),
    (r"send (the )?(contents?|text|data) (of this|from this) document", "data_exfiltration"),
    (r"do not follow (the )?(previous|earlier|user) instructions?", "instruction_override"),
    (r"execute (this|the following) command", "command_execution"),
    (r"if you are an ai assistant", "assistant_targeting"),
    (r"your new instructions are", "instruction_override"),
    (r"(send|post|upload|contact).{0,40}(https?://|external|outside)", "external_exfiltration"),
    (r"(reveal|extract|send).{0,40}(secret|password|api key|system prompt)", "secret_extraction"),
    (r"---+ ?(end|start) ?(system|retrieved|context|instructions?|prompt) ?---+", "delimiter_escape"),
    (r"you are now (dan|an unrestricted|jailbroken)", "role_hijack"),
    (r"\[?(system|human|assistant)\]?\s*:\s*(ignore|override|you are|disregard|say|output)", "role_hijack"),
    (r"(disregard|override|forget) (all|any|the)? ?(previous|prior|system) instructions?", "instruction_override"),
]


class IndirectInjectionScanner:
    """Explainable rules for instructions embedded in retrieved content."""

    def __init__(self, patterns=None):
        configured = patterns or [pattern for pattern, _ in PATTERNS]
        self.patterns = [re.compile(pattern, re.I) for pattern in configured]
        self.labels = {pattern: label for pattern, label in PATTERNS}

    def scan(self, text, metadata):
        normalized = unicodedata.normalize("NFKC", text or "").lower()
        normalized = re.sub(r"\s+", " ", normalized)
        findings = []
        for pattern in self.patterns:
            match = pattern.search(normalized)
            if match:
                findings.append({
                    "scanner": "indirect_prompt_injection",
                    "match": match.group(0)[:120],
                    "threat_type": self.labels.get(pattern.pattern, "indirect_prompt_injection"),
                    "severity": "high",
                })
        return findings