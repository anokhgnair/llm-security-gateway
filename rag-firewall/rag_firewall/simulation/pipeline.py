# SPDX-License-Identifier: Apache-2.0
"""Dual-Path Simulation Pipeline.

Provides isolated `run_unprotected()` and `run_protected()` execution flows,
wiring the protected path directly into `rag_firewall.firewall.Firewall.evaluate()`.
"""

import copy
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..firewall import Firewall
from .gemini_driver import GeminiDriver, GeminiResult
from .normalizer import normalize_context

# Sensitive data redaction patterns
SECRET_RE = re.compile(
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|"
    r"(?:sk|hf)_[A-Za-z0-9]{8,}|xox[abp]-[A-Za-z0-9-]{20,}|"
    r"Bearer\s+[A-Za-z0-9._=-]{20,}|(?:api[_\s-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9_-]{8,}|"
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
    re.I,
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?:\+?\d{1,3})?[\s.-]?(?:\(\d{2,4}\)|\d{2,4})[\s.-]?\d{3,4}[\s.-]?\d{3,4}")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def redact_sensitive_text(text: str) -> str:
    """Masks secrets and PII in-place with redaction markers."""
    sanitized = text or ""
    sanitized = SECRET_RE.sub("[REDACTED_SECRET]", sanitized)
    sanitized = EMAIL_RE.sub("[REDACTED_EMAIL]", sanitized)
    sanitized = PHONE_RE.sub("[REDACTED_PHONE]", sanitized)
    sanitized = SSN_RE.sub("[REDACTED_SSN]", sanitized)
    sanitized = CARD_RE.sub("[REDACTED_CARD]", sanitized)
    return sanitized


@dataclass
class PipelineResult:
    """Telemetry captured from a single pipeline execution path."""
    path: str  # "unprotected" or "protected"
    query: str
    response: str
    context_text: str
    chunks_in: int
    chunks_passed: int
    dropped_chunks: int
    findings: List[Dict[str, Any]] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    firewall_latency_ms: float = 0.0
    llm_latency_ms: float = 0.0
    total_latency_ms: float = 0.0
    driver_result: Optional[GeminiResult] = None
    retained_chunks: List[Dict[str, Any]] = field(default_factory=list)


class SimulationPipeline:
    """Simulation pipeline executing unprotected control benchmarks vs protected firewall paths."""

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        driver: Optional[GeminiDriver] = None,
        config_path: str = "firewall.yaml",
        normalize: bool = True,
    ):
        if firewall:
            self.firewall = firewall
        else:
            try:
                self.firewall = Firewall.from_yaml(config_path)
            except Exception:
                from ..scanners.conflict_scanner import ConflictScanner
                from ..scanners.encoding_scanner import EncodedContentScanner
                from ..scanners.indirect_injection_scanner import IndirectInjectionScanner
                from ..scanners.pii_scanner import PIIScanner
                from ..scanners.regex_scanner import RegexInjectionScanner
                from ..scanners.secrets_scanner import SecretsScanner
                from ..scanners.url_scanner import URLScanner
                self.firewall = Firewall(scanners=[
                    RegexInjectionScanner(),
                    IndirectInjectionScanner(),
                    PIIScanner(),
                    SecretsScanner(),
                    EncodedContentScanner(),
                    URLScanner(allowlist=["docs.myco.com", "intranet.myco.local"], denylist=["evil.example.com", "attacker-listener.com"]),
                    ConflictScanner(),
                ], policies=[
                    {"name": "block_denylisted_urls", "match": {"findings.reason": "denylist_domain"}, "action": "deny"},
                    {"name": "block_encoded_blobs", "match": {"findings.scanner": "encoded"}, "action": "deny"},
                ])

        self.driver = driver or GeminiDriver()
        self.normalize = normalize

    def run_unprotected(
        self,
        query: str,
        chunks: List[Dict[str, Any]],
        system_prompt: Optional[str] = None,
    ) -> PipelineResult:
        """Control Path: Dispatches raw, uninspected context directly to the Gemini CLI."""
        start_time = time.perf_counter()

        # Compile raw context directly without inspection
        raw_context = "\n\n".join(chunk.get("page_content", "") for chunk in chunks)
        prompt = self.driver.format_prompt(query, raw_context, system_prompt)

        driver_res = self.driver.run(prompt, system_prompt=system_prompt)
        total_latency = (time.perf_counter() - start_time) * 1000.0

        return PipelineResult(
            path="unprotected",
            query=query,
            response=driver_res.output,
            context_text=raw_context,
            chunks_in=len(chunks),
            chunks_passed=len(chunks),
            dropped_chunks=0,
            findings=[],
            actions=["ALLOW"] * len(chunks),
            firewall_latency_ms=0.0,
            llm_latency_ms=driver_res.latency_ms,
            total_latency_ms=round(total_latency, 2),
            driver_result=driver_res,
            retained_chunks=copy.deepcopy(chunks),
        )

    def run_protected(
        self,
        query: str,
        chunks: List[Dict[str, Any]],
        system_prompt: Optional[str] = None,
    ) -> PipelineResult:
        """Protected Path: Evaluates context via Firewall.evaluate(), drops malicious chunks, and redacts sensitive data."""
        start_time = time.perf_counter()
        fw_start = time.perf_counter()

        # Step 1: Pre-process & normalize encodings across chunks if enabled
        prepared_chunks: List[Dict[str, Any]] = []
        for c in chunks:
            doc = copy.deepcopy(c)
            text = doc.get("page_content", "")
            if self.normalize:
                norm_text, _ = normalize_context(text)
                doc["page_content"] = norm_text
            prepared_chunks.append(doc)

        # Step 2: Task 2.3 - Direct evaluation via Firewall.evaluate()
        evaluated_chunks = self.firewall.evaluate(prepared_chunks, context={"query": query})
        fw_latency_ms = (time.perf_counter() - fw_start) * 1000.0

        # Step 3: Enforce policy actions (ALLOW / REDACT / BLOCK)
        retained: List[Dict[str, Any]] = []
        all_findings: List[Dict[str, Any]] = []
        actions: List[str] = []

        for evaluated_doc in evaluated_chunks:
            meta = evaluated_doc.get("metadata", {})
            fw_meta = meta.get("_ragfw", {})
            decision = fw_meta.get("decision", "allow").lower()
            findings = fw_meta.get("findings", [])
            all_findings.extend(findings)

            if decision == "deny":
                actions.append("BLOCK")
                # Drop chunk entirely
                continue

            # Chunk passed - check for redaction requirements
            has_sensitive = any(f.get("scanner") in ("secrets", "pii") for f in findings)
            content = evaluated_doc.get("page_content", "")
            if has_sensitive:
                content = redact_sensitive_text(content)
                evaluated_doc["page_content"] = content
                actions.append("REDACT")
            else:
                actions.append("ALLOW")

            retained.append(evaluated_doc)

        # Step 4: Compile safe context
        if not retained:
            safe_context = "[NO CONTEXT PROVIDED - ALL RETRIEVED CHUNKS WERE BLOCKED BY FIREWALL POLICY]"
        else:
            safe_context = "\n\n".join(r.get("page_content", "") for r in retained)

        prompt = self.driver.format_prompt(query, safe_context, system_prompt)
        driver_res = self.driver.run(prompt, system_prompt=system_prompt)
        total_latency = (time.perf_counter() - start_time) * 1000.0

        return PipelineResult(
            path="protected",
            query=query,
            response=driver_res.output,
            context_text=safe_context,
            chunks_in=len(chunks),
            chunks_passed=len(retained),
            dropped_chunks=len(chunks) - len(retained),
            findings=all_findings,
            actions=actions,
            firewall_latency_ms=round(fw_latency_ms, 2),
            llm_latency_ms=driver_res.latency_ms,
            total_latency_ms=round(total_latency, 2),
            driver_result=driver_res,
            retained_chunks=retained,
        )
