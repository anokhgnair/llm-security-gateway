import re
from pathlib import Path
from typing import Dict, List

from ..provenance.hasher import Hasher


TOKEN_RE = re.compile(r"[a-z0-9]+")
STOPWORDS = {"a", "an", "and", "are", "for", "how", "is", "of", "the", "to", "what", "when", "where"}


class LocalRetriever:
    """Small deterministic lexical retriever for a local demo knowledge base."""

    def __init__(self, root="data/knowledge_base", top_k=3, chunk_size=900):
        self.root = Path(root)
        self.top_k = int(top_k)
        self.chunk_size = int(chunk_size)

    def _documents(self) -> List[dict]:
        documents = []
        if not self.root.exists():
            return documents
        for path in sorted(self.root.glob("*.txt")):
            text = path.read_text(encoding="utf-8", errors="replace")
            for index in range(0, max(1, len(text)), self.chunk_size):
                chunk = text[index:index + self.chunk_size].strip()
                if not chunk:
                    continue
                chunk_id = f"{path.stem}_{index // self.chunk_size + 1:02d}"
                documents.append({
                    "page_content": chunk,
                    "metadata": {
                        "source": path.name,
                        "source_type": "local_document",
                        "chunk_id": chunk_id,
                        "hash": Hasher.hash_text(chunk),
                    },
                })
        return documents

    @staticmethod
    def _score(query: str, text: str) -> float:
        query_tokens = set(TOKEN_RE.findall(query.lower())) - STOPWORDS
        text_tokens = TOKEN_RE.findall(text.lower())
        if not query_tokens:
            return 0.0
        matches = sum(text_tokens.count(token) for token in query_tokens)
        return matches / max(1, len(text_tokens) ** 0.5)

    def retrieve(self, query: str, top_k=None) -> List[dict]:
        scored = []
        for document in self._documents():
            score = self._score(query, document["page_content"])
            if score > 0:
                scored.append((score, document))
        scored.sort(key=lambda item: (-item[0], item[1]["metadata"]["source"]))
        results = []
        for score, document in scored[:top_k or self.top_k]:
            document["metadata"]["relevance"] = score
            results.append(document)
        return results

    def count(self) -> int:
        return len({item["metadata"]["source"] for item in self._documents()})