import io
import os


def extract_text(filename: str, content: bytes) -> str:
    if os.path.splitext(filename)[1].lower() == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise RuntimeError("PDF support requires the gateway extra: pip install 'llm-secgate[gateway]'") from exc
        return "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(content)).pages)
    return content.decode("utf-8", errors="replace")