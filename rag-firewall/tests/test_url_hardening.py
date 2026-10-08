from rag_firewall.scanners.url_scanner import URLScanner


def test_url_scanner_flags_ip_literals():
    s = URLScanner()
    text = "connect to http://192.168.1.10:8080 and https://2001:0db8:85a3::8a2e:0370:7334"
    findings = s.scan(text, {})
    reasons = {f.get("reason") for f in findings}
    matches = {f.get("match") for f in findings}
    assert "ip_literal" in reasons
    assert "192.168.1.10" in matches or any("192.168.1.10" in m for m in matches)


def test_url_scanner_flags_punycode_hosts():
    s = URLScanner()
    text = "see http://xn--e1afmkfd.xn--p1ai/docs"
    findings = s.scan(text, {})
    reasons = [f.get("reason") for f in findings]
    assert any(r == "punycode_host" for r in reasons)


def test_url_scanner_allow_and_deny_with_hardening():
    s = URLScanner(allowlist=["good.example.com"], denylist=["evil.example.com"])
    text = "See https://good.example.com/x and https://evil.example.com/y and http://10.0.0.5"
    findings = s.scan(text, {})
    by_reason = {}
    for f in findings:
        by_reason.setdefault(f.get("reason"), []).append(f)
    # denylist triggers high severity
    assert any(f.get("severity") == "high" for f in by_reason.get("denylist_domain", []))
    # non-allowlisted triggers high severity
    assert any(f.get("severity") == "high" for f in by_reason.get("non_allowlisted_domain", []))
    # ip literal is flagged separately
    assert any(f.get("reason") == "ip_literal" for f in findings)
