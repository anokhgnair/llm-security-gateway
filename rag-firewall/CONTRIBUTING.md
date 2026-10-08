# Contributing to RAGShield Gateway

RAGShield Gateway is a local-first security gateway for RAG and LLM applications. Contributions should preserve its central security boundary: untrusted retrieved data is never treated as instructions.

## Development

Use the intended Python 3.11 interpreter on Windows:

```powershell
C:\Users\NIRANJAN\AppData\Local\Programs\Python\Python311\python.exe -m pip install -e ".[gateway,dev]"
C:\Users\NIRANJAN\AppData\Local\Programs\Python\Python311\python.exe -m pytest -q
```

## Contribution Guidelines

- Add deterministic tests for new security behavior.
- Keep document processing local and avoid unnecessary network calls.
- Document false-positive and policy tradeoffs.
- Keep scanner implementations modular.
- Preserve public compatibility for existing `rag_firewall` imports unless migration is explicitly planned.
- Preserve Apache-2.0 licensing and attribution.
- Do not include real credentials or personal data in fixtures.

## Security Reports

Do not publish sensitive vulnerability details in a public issue. Provide a minimal reproduction privately to the project maintainers.
