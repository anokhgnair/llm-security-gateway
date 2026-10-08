### `ARCH.md`

```markdown
# Architectural Specification: LLM Security Gateway & Simulation Engine

## 1. High-Level Topology

The gateway operates as an inline reverse proxy and context-sanitization layer positioned between data retrieval systems, customer context inputs, and the Gemini execution runtime.

┌────────────────────────────────────────┐
              │             Data Ingestion             │
              │   (Vector DB / PDFs / Emails / Tools)  │
              └───────────────────┬────────────────────┘
                                  │ (Poisoned Context)
                                  ▼
                  ┌──────────────────────────────┐
                  │    RAG Firewall Mediation    │
                  └───────┬──────────────┬───────┘
      Unprotected Path    │              │ Protected Path
     (Control Benchmark)  │              ▼
                          │   ┌─────────────────────────┐
                          │   │   Encoding Normalizer   │
                          │   └──────────┬──────────────┘
                          │              ▼
                          │   ┌─────────────────────────┐
                          │   │ Pluggable Scanner Suite │
                          │   │ - Indirect Injection    │
                          │   │ - Secrets / PII         │
                          │   │ - URL & Smuggling       │
                          │   └──────────┬──────────────┘
                          │              ▼
                          │   ┌─────────────────────────┐
                          │   │ Declarative Policy Rule │
                          │   │ (ALLOW / REDACT / BLOCK)│
                          │   └──────────┬──────────────┘
                          │              ▼
                          │   ┌─────────────────────────┐
                          │   │ Provenance SHA Auditing │
                          │   └──────────┬──────────────┘
                          │              │ Sanitized Context
                          ▼              ▼
                 ┌────────────────────────────────┐
                 │     Gemini CLI Test Driver     │
                 │  (gemini -p / System Prompts)  │
                 └───────────────┬────────────────┘
                                 │
                 ┌───────────────▼────────────────┐
                 │   Comparative Telemetry Hub    │
                 │   (Diffs, Exploit Status, KPIs)│
                 └────────────────────────────────┘

---

## 2. Core Subsystems

### 2.1 Context Pre-Processing & Encoding Scanner
* Normalizes multi-layer obfuscation vectors (Base64 fragments, Hex blocks, URL encodings, zero-width space smuggling).
* Translates concealed payloads into standard UTF-8 text before passing chunks to pattern-matching rules.

### 2.2 Inspection & Policy Decisioning Engine
* **Concurrent Scanning**: Chunks are processed across isolated scanner modules:
  * `indirect_injection_scanner.py`: Delimiter escape sequences (`---END SYSTEM---`), role hijacking (`You are now Dan`), and instruction override commands.
  * `secrets_scanner.py` & `pii_scanner.py`: High-entropy string checks, regex token filters (AWS, GitHub, JWT), and identity fields.
  * `url_scanner.py`: Exfiltration domain classification and markdown image injection detection (`![exfil](https://...)`).
* **Deterministic Rules (`firewall.yaml`)**: Maps scanner findings to decisive actions:
  * `ALLOW`: Context passes unchanged.
  * `REDACT`: Sensitive values or malicious snippets are masked in-place with `[REDACTED]`.
  * `BLOCK`: The context chunk is dropped entirely, preventing inclusion in the model prompt.

### 2.3 Gemini CLI Invocation Bridge
* Abstracted execution driver interfacing directly with the installed Gemini CLI binary via headless subprocess pipes.
* Formats system prompts, user queries, and contextual payloads into isolated command arguments, avoiding prompt interpolation leaks.
* Captures standard output, exit codes, and execution latency.

### 2.4 Comparative Evaluation & Telemetry Hub
* Dual-execution runner dispatching two calls per scenario:
  1. **Control Run (Unprotected)**: Passes raw context directly to the Gemini CLI.
  2. **Experimental Run (Protected)**: Evaluates context through the firewall, compiles sanitized chunks, and routes safe text to the Gemini CLI.
* Verifies presence of canary tokens (e.g., `PWNED`, leaked secrets, unauthorized external URLs) in both responses to generate deterministic exploit status reports.
