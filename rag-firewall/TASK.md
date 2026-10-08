# 10-Hour Implementation Task Backlog

## Timeline Overview
* **Hours 0 – 2**: Project Scaffolding, Gemini CLI Setup & Verification
* **Hours 2 – 5**: Core Simulation Engine & Pipeline Implementation
* **Hours 5 – 7**: Attack Test Corpus & Exploit Verification Logic
* **Hours 7 – 9**: Comparative Evaluation Runner & Rich CLI Reporting
* **Hours 9 – 10**: End-to-End Testing, Documentation, & Demo Dry-Run

---

### Phase 1: Environment & Setup (Hours 0 – 2)
- [x] **Task 1.1**: Verify Python 3.11 environment and install dependencies (`pip install -e . rich pydantic`).
- [x] **Task 1.2**: Validate Gemini CLI connectivity locally via headless command line test.
- [x] **Task 1.3**: Validate existing `firewall.yaml` and schema definitions using `test_config_validation.py`.

### Phase 2: Simulation Harness Engineering (Hours 2 – 5)
- [x] **Task 2.1**: Implement `rag_firewall/simulation/gemini_driver.py` to handle headless subprocess calls to the Gemini CLI.
- [x] **Task 2.2**: Implement `rag_firewall/simulation/pipeline.py` providing isolated `run_unprotected()` and `run_protected()` execution flows.
- [x] **Task 2.3**: Wire the protected pipeline directly into `rag_firewall.firewall.Firewall.evaluate()`.

### Phase 3: Attack Corpus & Verification Logic (Hours 5 – 7)
- [x] **Task 3.1**: Build `rag_firewall/simulation/scenarios.py` with 4 distinct vectors:
  - Vector A: Delimiter Hijack & Instruction Override.
  - Vector B: Markdown Exfiltration URL Smuggling.
  - Vector C: Encoded Base64 Payload Bypass.
  - Vector D: Benign Business Policy (Control for False Positives).
- [x] **Task 3.2**: Implement canary-detection parser to inspect Gemini outputs for target strings.

### Phase 4: Comparative Reporting & Polish (Hours 7 – 9)
- [x] **Task 4.1**: Implement `rag_firewall/simulation/runner.py` with terminal side-by-side diff reporting using `rich.table` and `rich.console`.
- [x] **Task 4.2**: Add JSON report export (`--output results.json`) recording policy actions, rules triggered, and mitigation outcomes.

### Phase 5: Verification & Demo Readiness (Hours 9 – 10)
- [x] **Task 5.1**: Execute automated simulation run across all test vectors; verify 100% exploit interception.
- [x] **Task 5.2**: Perform complete dry-run demo sequence from a clean shell session.
- [x] **Task 5.3**: Final commit and tag for delivery.