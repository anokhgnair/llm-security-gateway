# LLM-SecGate Roadmap

LLM-SecGate is a local-first LLM security gateway focused on protecting the boundaries around retrieval and generation.

## Current Foundation

- Direct and indirect prompt-injection detection.
- Secret, PII, encoded-content, URL, and stale-content scanners.
- Policy enforcement, risk scoring, trust scoring, provenance, and audit logging.
- Local lexical retrieval with malicious-document fixtures.
- Optional Ollama generation and output security.
- FastAPI gateway, dashboard, attack simulator, and measured dataset evaluation.

## Possible Enhancements

- More explainable prompt-injection and secret patterns.
- More deterministic retriever adapters.
- Additional local document formats.
- Dry-run policy evaluation.
- Expanded adversarial fixtures and benchmark reporting.
- Additional framework integrations.

## Deliberately Out of Scope

Custom ML training, transformer security models, malware sandboxing, browser isolation, enterprise IAM/RBAC, blockchain, Kubernetes deployment, distributed-agent security, external threat intelligence, internet crawling, and complex multi-agent orchestration are outside the current hackathon MVP.

## Contribution Principle

Every new retrieval or generation path must preserve the rule that untrusted data is inspected before it can enter model context.
