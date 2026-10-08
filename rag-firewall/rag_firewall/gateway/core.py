import re
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional
from pathlib import Path
import yaml

from ..audit import Audit
from ..firewall import Firewall
from ..provenance.hasher import Hasher
from ..provenance.store import ProvenanceStore
from ..scanners.conflict_scanner import ConflictScanner
from ..scanners.encoding_scanner import EncodedContentScanner
from ..scanners.indirect_injection_scanner import IndirectInjectionScanner
from ..scanners.pii_scanner import PIIScanner
from ..scanners.regex_scanner import RegexInjectionScanner
from ..scanners.secrets_scanner import SecretsScanner
from ..scanners.url_scanner import URLScanner
from .llm import OllamaClient, fallback_answer
from .retriever import LocalRetriever


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

WEIGHTS = {
    "regex_injection": 50,
    "indirect_prompt_injection": 45,
    "secrets": 40,
    "pii": 25,
    "url": 30,
    "encoded": 25,
    "conflict": 10,
}


def _unique(values: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(value for value in values if value))


class SecurityGateway:
    """RAGShield facade over the retained firewall engine."""

    def __init__(self, firewall: Optional[Firewall] = None, provenance: Optional[ProvenanceStore] = None,
                 retriever: Optional[LocalRetriever] = None, llm: Optional[OllamaClient] = None,
                 block_dangerous_urls: bool = True):
        self.firewall = firewall or Firewall(scanners=[
            RegexInjectionScanner(), IndirectInjectionScanner(), PIIScanner(), SecretsScanner(),
            EncodedContentScanner(), URLScanner(denylist=["evil.example.com"]), ConflictScanner(),
        ])
        self.provenance = provenance
        self.retriever = retriever or LocalRetriever()
        self.llm = llm or OllamaClient(enabled=False)
        self.block_dangerous_urls = block_dangerous_urls

    @classmethod
    def from_yaml(cls, path: str, provenance: Optional[ProvenanceStore] = None) -> "SecurityGateway":
        config = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        retrieval = config.get("retrieval", {})
        llm_config = config.get("llm", {})
        security = config.get("security", {})
        return cls(
            Firewall.from_yaml(path), provenance=provenance,
            retriever=LocalRetriever(retrieval.get("knowledge_base", "data/knowledge_base"),
                                     retrieval.get("top_k", 3), retrieval.get("chunk_size", 900)),
            llm=OllamaClient(llm_config.get("base_url", "http://127.0.0.1:11434"),
                             llm_config.get("model", "llama3.2:3b"),
                             llm_config.get("enabled", False),
                             llm_config.get("timeout", 30)),
            block_dangerous_urls=security.get("block_denylisted_urls", True),
        )

    def _trust_score(self, text: str, metadata: Dict[str, Any], findings: List[dict]) -> int:
        score = int(metadata.get("trust_score", 0) or 0)
        document_hash = metadata.get("hash") or Hasher.hash_text(text)
        if metadata.get("source"):
            score += 20
        if metadata.get("hash"):
            score += 20
        record = self.provenance.get(document_hash) if self.provenance else None
        if record:
            score += 20
        timestamp = metadata.get("timestamp")
        if timestamp and time.time() - float(timestamp) < 90 * 86400:
            score += 20
        if not any(f.get("scanner") == "url" and f.get("severity") == "high" for f in findings):
            score += 20
        return min(100, score)

    @staticmethod
    def _sanitize(text: str, findings: List[dict]) -> str:
        sanitized = text or ""
        scanners = {finding.get("scanner") for finding in findings}
        if "secrets" in scanners:
            sanitized = SECRET_RE.sub("[REDACTED_SECRET]", sanitized)
        if "pii" in scanners:
            sanitized = EMAIL_RE.sub("[REDACTED_EMAIL]", sanitized)
            sanitized = PHONE_RE.sub("[REDACTED_PHONE]", sanitized)
            sanitized = SSN_RE.sub("[REDACTED_SSN]", sanitized)
            sanitized = CARD_RE.sub("[REDACTED_CARD]", sanitized)
        return sanitized

    @staticmethod
    def _redact_audit_text(text: Optional[str]) -> str:
        sanitized = text or ""
        sanitized = SECRET_RE.sub("[REDACTED_SECRET]", sanitized)
        sanitized = EMAIL_RE.sub("[REDACTED_EMAIL]", sanitized)
        sanitized = PHONE_RE.sub("[REDACTED_PHONE]", sanitized)
        sanitized = SSN_RE.sub("[REDACTED_SSN]", sanitized)
        return CARD_RE.sub("[REDACTED_CARD]", sanitized)

    def scan(self, text: str, source: str = "user", metadata: Optional[Dict[str, Any]] = None,
             request_id: Optional[str] = None, sanitize: bool = True, query: Optional[str] = None) -> Dict[str, Any]:
        started = time.perf_counter()
        metadata = dict(metadata or {})
        metadata.setdefault("source", source)
        doc = {"page_content": text or "", "metadata": metadata}
        decision, findings = self.firewall.decide(doc, context={"source": source, "request_id": request_id})
        dangerous_url = any(
            finding.get("scanner") == "url" and finding.get("severity") == "high"
            and finding.get("reason") in ("denylist_domain", "ip_literal", "punycode_host", "non_allowlisted_domain")
            for finding in findings
        )
        if self.block_dangerous_urls and dangerous_url:
            decision["action"] = "deny"
            decision.setdefault("reasons", []).append("gateway:dangerous-url")
        risk = 0
        for scanner in {finding.get("scanner") for finding in findings}:
            risk += WEIGHTS.get(scanner, 0)
        risk = min(100, risk + max(0, len(findings) - 1) * 5)
        threats = _unique(
            "prompt_injection" if finding.get("scanner") == "regex_injection" else
            "indirect_prompt_injection" if finding.get("scanner") == "indirect_prompt_injection" else
            finding.get("scanner", "unknown")
            for finding in findings
        )
        explanations = _unique(
            {
                "regex_injection": "Instruction override or jailbreak language detected.",
                "indirect_prompt_injection": "Retrieved content contains instructions targeting the assistant or hierarchy.",
                "secrets": "A credential-like token was detected; its value is never returned.",
                "pii": "Personal information was detected.",
                "url": "A URL requires local allowlist or denylist policy review.",
                "encoded": "Encoded content may conceal instructions or sensitive data.",
                "conflict": "The source is stale or marked deprecated.",
            }.get(finding.get("scanner"), "Security finding detected.")
            for finding in findings
        )
        if decision.get("action") == "deny":
            action, explanation = "BLOCK", "The firewall policy rejected this content."
        elif "pii" in {finding.get("scanner") for finding in findings} and sanitize:
            action, explanation = "SANITIZE", "Personal information was removed before downstream use."
        else:
            action, explanation = "ALLOW", "No blocking policy matched this content."
        if explanations:
            explanation = " ".join(explanations)
        output_text = self._sanitize(text, findings) if action == "SANITIZE" else (text if action == "ALLOW" else None)
        event = {
            "event_type": "security_decision", "timestamp": time.time(), "request_id": request_id or str(uuid.uuid4()), "source": source, "query": self._redact_audit_text(query),
            "threat_types": threats, "risk_score": risk, "trust_score": self._trust_score(text, metadata, findings),
            "decision": action, "sanitized": action == "SANITIZE", "blocked": action == "BLOCK",
            "explanation": explanation, "findings": findings,
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        }
        Audit.log(event)
        return {
            "request_id": event["request_id"], "decision": action, "risk_score": risk,
            "risk_level": "SAFE" if risk < 30 else "SUSPICIOUS" if risk < 60 else "HIGH RISK" if risk < 80 else "CRITICAL",
            "trust_score": event["trust_score"], "threats": threats, "explanations": explanations,
            "explanation": explanation, "sanitized": event["sanitized"], "text": output_text,
            "findings": findings,
        }

    def query(self, text: str, documents: Optional[List[dict]] = None, source: str = "query") -> Dict[str, Any]:
        started = time.perf_counter()
        request_id = str(uuid.uuid4())
        user_result = self.scan(text, source=source, request_id=request_id, query=text)
        if user_result["decision"] == "BLOCK":
            return {
                "request_id": request_id, "answer": "The query was blocked by the security gateway.",
                "decision": "BLOCK", "risk_score": user_result["risk_score"],
                "trust_score": user_result["trust_score"], "sources": [], "blocked_sources": [],
                "threats": user_result["threats"], "security_explanation": user_result["explanation"],
                "input": user_result, "documents": [], "retrieved_documents": [], "safe_context": [], "context_blocked": 0,
                "findings": user_result["findings"], "sanitized": False,
                "llm_provider": "ollama", "llm_model": getattr(self.llm, "model", None),
                "llm_status": "skipped_input_blocked", "llm_called": False,
                "llm_latency": 0.0, "total_latency": round((time.perf_counter() - started) * 1000, 3),
                "stage_status": {"input_scan": "BLOCK", "retrieval": "SKIPPED", "document_scan": "SKIPPED", "ollama": "SKIPPED", "output_scan": "SKIPPED"},
                "blocked_reason": user_result["explanation"],
            }
        retrieval_started = time.perf_counter()
        retrieved = documents if documents is not None else self.retriever.retrieve(text)
        retrieval_latency = round((time.perf_counter() - retrieval_started) * 1000, 3)
        safe_context = []
        safe_documents = []
        document_results = []
        retrieved_documents = []
        blocked_sources = []
        all_threats = list(user_result["threats"])
        document_started = time.perf_counter()
        for document in retrieved:
            metadata = document.get("metadata", {})
            result = self.scan(document.get("page_content", document.get("text", "")),
                               source=metadata.get("source", "retrieved"), metadata=metadata, request_id=request_id)
            document_results.append(result)
            retrieved_documents.append({
                "source": metadata.get("source", "retrieved"),
                "chunk_id": metadata.get("chunk_id"),
                "relevance": metadata.get("relevance", 0.0),
                "decision": result["decision"],
                "risk_score": result["risk_score"],
                "trust_score": result["trust_score"],
            })
            all_threats.extend(result["threats"])
            if result["decision"] == "BLOCK":
                blocked_sources.append(metadata.get("source", "retrieved"))
            if result["decision"] != "BLOCK" and result.get("text") is not None:
                safe_context.append(result["text"])
                safe_documents.append({"page_content": result["text"], "metadata": metadata})
        document_latency = round((time.perf_counter() - document_started) * 1000, 3)
        llm_started = time.perf_counter()
        llm_called = bool(safe_documents and getattr(self.llm, "enabled", False))
        generated = self.llm.generate(text, safe_documents) if llm_called else None
        llm_latency = getattr(self.llm, "last_latency_ms", round((time.perf_counter() - llm_started) * 1000, 3)) if llm_called else 0.0
        llm_status = getattr(self.llm, "last_status", "disabled") if llm_called else ("skipped_no_trusted_context" if not safe_documents else "disabled")
        answer = generated or fallback_answer(text, safe_documents)
        output_result = self.scan(answer, source="llm_output", request_id=request_id, sanitize=True, query=text)
        if output_result["decision"] == "BLOCK":
            answer = "The generated response was blocked by the output security layer."
        elif output_result.get("text") is not None:
            answer = output_result["text"]
        risk_score = max([user_result["risk_score"], output_result["risk_score"]] + [item["risk_score"] for item in document_results])
        trust_values = [item["trust_score"] for item in document_results]
        trust_score = round(sum(trust_values) / len(trust_values)) if trust_values else user_result["trust_score"]
        decision = "BLOCK" if blocked_sources else ("SANITIZE" if any(item["decision"] == "SANITIZE" for item in document_results) else "ALLOW")
        stage_status = {
            "input_scan": "PASS",
            "retrieval": "PASS" if retrieved else "WARNING",
            "document_scan": "BLOCK" if blocked_sources else ("PASS" if retrieved else "WARNING"),
            "safe_context": "PASS" if safe_documents else "WARNING",
            "ollama": "PASS" if generated else ("SKIPPED" if not llm_called else "FALLBACK"),
            "output_scan": "BLOCK" if output_result["decision"] == "BLOCK" else ("SANITIZED" if output_result["sanitized"] else "PASS"),
        }
        all_findings = list(user_result["findings"])
        for item in document_results:
            all_findings.extend(item["findings"])
        all_findings.extend(output_result["findings"])
        return {
            "request_id": request_id, "answer": answer, "decision": decision,
            "risk_score": risk_score, "trust_score": trust_score,
            "sources": [item["metadata"].get("source", "unknown") for item in safe_documents],
            "blocked_sources": blocked_sources, "threats": _unique(all_threats),
            "security_explanation": "Blocked retrieved content was excluded before response generation." if blocked_sources else "Retrieved content passed the security policy.",
            "input": user_result, "documents": document_results, "retrieved_documents": retrieved_documents,
            "safe_context": safe_context, "context_blocked": len(blocked_sources), "output_security": output_result,
            "findings": all_findings, "sanitized": output_result["sanitized"] or any(item["decision"] == "SANITIZE" for item in document_results),
            "llm_provider": "ollama", "llm_model": getattr(self.llm, "model", None), "llm_status": llm_status,
            "llm_called": llm_called, "llm_latency": llm_latency,
            "total_latency": round((time.perf_counter() - started) * 1000, 3),
            "stage_status": stage_status,
            "stage_latency_ms": {"retrieval": retrieval_latency, "document_firewall": document_latency, "llm": llm_latency},
            "blocked_reason": "One or more retrieved documents were blocked." if blocked_sources else None,
        }

    def health(self) -> Dict[str, Any]:
        if hasattr(self.llm, "status"):
            llm_status = self.llm.status()
        else:
            llm_status = {"provider": "ollama", "status": "ready" if self.llm.available() else "unavailable", "model": getattr(self.llm, "model", None)}
        llm_ready = llm_status["status"] == "ready"
        return {
            "status": "healthy" if llm_ready or not getattr(self.llm, "enabled", False) else "degraded",
            "firewall": "ready", "retriever": "ready",
            "llm": llm_status,
            "documents": self.retriever.count(),
        }