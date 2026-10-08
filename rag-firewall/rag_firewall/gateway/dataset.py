import json
import time
from pathlib import Path
from typing import Dict, List

from .core import SecurityGateway


def evaluate_dataset(path: str, gateway: SecurityGateway = None) -> Dict[str, float]:
    service = gateway or SecurityGateway()
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    started = time.perf_counter()
    true_positives = false_positives = false_negatives = true_negatives = 0
    for row in rows:
        result = service.scan(row["text"], source="dataset")
        expected = row["expected"]
        has_finding = bool(result["threats"])
        if expected == "safe":
            false_positives += int(has_finding)
            true_negatives += int(not has_finding)
        else:
            true_positives += int(has_finding)
            false_negatives += int(not has_finding)
    elapsed = time.perf_counter() - started
    return {
        "samples": len(rows), "true_positives": true_positives, "false_positives": false_positives,
        "false_negatives": false_negatives, "true_negatives": true_negatives,
        "detection_rate": round(true_positives / (true_positives + false_negatives), 3) if true_positives + false_negatives else 0.0,
        "false_positive_rate": round(false_positives / (false_positives + true_negatives), 3) if false_positives + true_negatives else 0.0,
        "average_latency_ms": round(elapsed * 1000 / len(rows), 3) if rows else 0.0,
    }