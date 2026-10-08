# SPDX-License-Identifier: Apache-2.0
"""Automated tests for Verification Studio API and Dashboard."""

from fastapi.testclient import TestClient

from rag_firewall.gateway.app import create_app
from rag_firewall.gateway.core import SecurityGateway
from rag_firewall.gateway.verification import BEAST_SCENARIOS, VerificationEngine


def test_api_scenarios_endpoint():
    client = TestClient(create_app(SecurityGateway()))
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    data = res.json()
    assert "scenarios" in data
    assert len(data["scenarios"]) >= 5
    ids = [s["id"] for s in data["scenarios"]]
    assert "vector_a_delimiter_hijack" in ids
    assert "vector_b_markdown_url_smuggling" in ids
    assert "vector_c_base64_encoded_payload" in ids
    assert "vector_d_benign_business_policy" in ids


def test_api_verify_compare_mode():
    client = TestClient(create_app(SecurityGateway()))
    sc = BEAST_SCENARIOS[0]
    payload = {
        "query": sc["query"],
        "context": sc["context"],
        "canary": sc["canary"],
        "compare_mode": True,
        "model": "simulation",
        "is_attack": sc["is_attack"],
    }
    res = client.post("/api/verify", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["mode"] == "compare"
    assert data["verdict"] in ("MITIGATED", "BLOCKED_PROACTIVELY")
    assert data["unprotected"]["canary_leaked"] is True
    assert data["protected"]["canary_leaked"] is False
    assert "BLOCK" in data["protected"]["actions"]
    assert data["overhead_ms"] >= 0


def test_api_verify_single_toggle_mode_on_vs_off():
    client = TestClient(create_app(SecurityGateway()))
    sc = BEAST_SCENARIOS[0]
    
    # Run with Gateway OFF (vulnerable)
    res_off = client.post("/api/verify", json={
        "query": sc["query"],
        "context": sc["context"],
        "canary": sc["canary"],
        "gateway_enabled": False,
        "compare_mode": False,
        "model": "simulation",
        "is_attack": True,
    })
    assert res_off.status_code == 200
    off_data = res_off.json()
    assert off_data["gateway_enabled"] is False
    assert off_data["execution"]["canary_leaked"] is True
    assert "EXPLOIT" in off_data["status"]

    # Run with Gateway ON (protected)
    res_on = client.post("/api/verify", json={
        "query": sc["query"],
        "context": sc["context"],
        "canary": sc["canary"],
        "gateway_enabled": True,
        "compare_mode": False,
        "model": "simulation",
        "is_attack": True,
    })
    assert res_on.status_code == 200
    on_data = res_on.json()
    assert on_data["gateway_enabled"] is True
    assert on_data["execution"]["canary_leaked"] is False
    assert on_data["status"] == "MITIGATED"
    assert "BLOCK" in on_data["execution"]["actions"]


def test_api_verify_benign_control():
    client = TestClient(create_app(SecurityGateway()))
    benign_sc = next(s for s in BEAST_SCENARIOS if s["id"] == "vector_d_benign_business_policy")
    res = client.post("/api/verify", json={
        "query": benign_sc["query"],
        "context": benign_sc["context"],
        "canary": benign_sc["canary"],
        "compare_mode": True,
        "model": "simulation",
        "is_attack": False,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "BENIGN_RETAINED"
    assert "ALLOW" in data["protected"]["actions"]
    assert data["protected"]["canary_leaked"] is True  # expected fact present in safe output


def test_dashboard_renders_studio_elements():
    client = TestClient(create_app(SecurityGateway()))
    res = client.get("/dashboard")
    assert res.status_code == 200
    html = res.text
    assert "RAGShield Gateway" in html
    assert "gateway-toggle" in html
    assert "tactical-switch" in html
    assert "btn-mode-compare" in html
    assert "scenarios-carousel" in html
