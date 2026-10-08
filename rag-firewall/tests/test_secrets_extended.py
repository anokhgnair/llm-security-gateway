from rag_firewall.scanners.secrets_scanner import SecretsScanner


def test_huggingface_and_databricks_and_slack_webhook_detected():
    s = SecretsScanner()
    text = "hf_abcdefghijklmnopqrstuvwxyzABCDE dapiABCDEFGHIJKLMNOPQRSTUVWX https://hooks.slack.com/services/T12345/A12345/ABCDEFghijklmnop"
    findings = s.scan(text, {})
    names = {f.get("match") for f in findings}
    assert "huggingface_token" in names
    assert "databricks_token" in names
    assert "slack_webhook" in names


def test_azure_like_and_generic_secret_detected():
    s = SecretsScanner()
    text = "AZURE_SECRET_ABCDEFGH secret_abcdefghijklmnopqrstuvwxyz123456"
    findings = s.scan(text, {})
    names = {f.get("match") for f in findings}
    assert "azure_secret_suspect" in names or any("azure" in n for n in names)
    assert "generic_secret_token" in names
