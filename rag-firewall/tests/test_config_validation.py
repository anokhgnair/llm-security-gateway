import os, json, tempfile
import pytest

from rag_firewall.firewall import Firewall

VALID_CFG = {
    "scanners": [
        {"type": "regex_injection"},
        {"type": "secrets"},
        {"type": "url", "allowlist": ["good.example.com"], "denylist": ["evil.example.com"]},
        {"type": "conflict", "stale_days": 120}
    ],
    "policies": [
        {"name": "allow_default", "action": "allow"}
    ]
}

INVALID_ACTION_CFG = {
    "scanners": [ {"type": "regex_injection"} ],
    "policies": [ {"name": "bad", "action": "block"} ]  # not in enum
}

INVALID_SCANNER_TYPE_CFG = {
    "scanners": [ {"type": "unknown_scanner"} ],
    "policies": [ {"name": "allow_default", "action": "allow"} ]
}

def _write_tmp_yaml(obj):
    import yaml
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        yaml.safe_dump(obj, f)
    return path

@pytest.mark.parametrize("cfg", [VALID_CFG])
def test_valid_config_passes_validation(cfg):
    path = _write_tmp_yaml(cfg)
    # Should not raise; might skip validation if jsonschema not installed
    fw = Firewall.from_yaml(path)
    assert isinstance(fw, Firewall)

@pytest.mark.parametrize("cfg", [INVALID_ACTION_CFG, INVALID_SCANNER_TYPE_CFG])
def test_invalid_config_raises_when_jsonschema_present(cfg):
    try:
        import jsonschema  # noqa: F401
    except Exception:
        pytest.skip("jsonschema not installed; validation is optional")
    path = _write_tmp_yaml(cfg)
    with pytest.raises(ValueError):
        Firewall.from_yaml(path)
