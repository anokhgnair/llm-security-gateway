# Product Requirements Document (PRD)

## 1. Executive Summary
Companies deploying LLM-powered enterprise assistants face critical risks from indirect prompt injection attacks embedded inside unvetted data sources (customer emails, uploaded PDFs, knowledge base updates). This project delivers an automated security gateway and validation harness that inspects context at retrieval time, blocks exploits, and proves security efficacy via Gemini CLI simulations.

---

## 2. Personas & Stakeholders
* **AI Application Engineer**: Needs drop-in middleware to protect RAG agents without rewriting application pipelines.
* **SecOps / Security Architect**: Demands declarative policy management (`firewall.yaml`), verifiable audit trails, and zero credential leakage.
* **Product Reviewer / Evaluator**: Requires clear, visual, side-by-side evidence comparing vulnerable vs protected LLM behavior.

---

## 3. Functional Requirements

| ID | Capability | Description | Priority |
| :--- | :--- | :--- | :--- |
| **FR-1** | **Indirect Injection Interception** | Detect and neutralize instruction overrides, markdown link smuggling, and role-break prompts inside document chunks. | **P0** |
| **FR-2** | **Sensitive Data Leak Defense** | Mask PII and high-entropy credentials (API keys, tokens) before injection into generation prompts. | **P0** |
| **FR-3** | **Gemini CLI Simulation Runner** | Headless CLI wrapper that executes dual-path runs (`Unprotected vs. Protected`) across automated attack vectors. | **P0** |
| **FR-4** | **Configurable Policy Actioning** | Support `ALLOW`, `REDACT`, and `BLOCK` directives configurable via validated YAML schemas. | **P1** |
| **FR-5** | **Automated Exploit Verification** | Deterministic canary detection checking whether target tokens/exfiltration links surfaced in LLM outputs. | **P1** |
| **FR-6** | **Telemetry & Export Engine** | Export benchmark summaries (decision metrics, latency impact, pass/fail status) to JSON and terminal tables. | **P2** |

---

## 4. Non-Functional Requirements
* **Zero Local GPU Requirement**: The entire testing and simulation framework must run seamlessly on standard laptops using the Gemini CLI.
* **Low Latency Overhead**: Total scanner processing time must remain below 120ms per 4KB text chunk.
* **Fail-Secure Architecture**: If an unhandled exception occurs in a scanner during policy enforcement, the chunk must be blocked (`fail-closed`).
* **Zero System Prompt Tampering**: Context boundary indicators must prevent LLMs from confusing context text with system instructions.

---

## 5. Success Metrics
* **Exploit Mitigation Rate**: 100% of tested canary exfiltrations and instruction overrides must be neutralized in the protected pipeline.
* **Benign Context Retention**: >95% of normal enterprise policy documentation must pass through with action `ALLOW`.
* **Execution Reliability**: Clean side-by-side execution runs without manual intervention within the 10-hour build window.