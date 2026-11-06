"""Integration tests: API + trained models + database."""

from conftest import NEPTUNE_ROW, NORMAL_ROW, row_to_features


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_dos_traffic_raises_alert_and_blocks_ip(client):
    body = {"source_ip": "198.51.100.9", "features": row_to_features(NEPTUNE_ROW)}
    res = client.post("/api/analyze/traffic", json=body).json()
    assert res["label"] == "DoS"
    assert res["is_threat"] is True
    assert res["severity"] == "High"
    assert res["blocked"] is True

    blocked = [b["ip"] for b in client.get("/api/blocklist").json()]
    assert "198.51.100.9" in blocked

    # Second request from the same IP is dropped without a new alert.
    again = client.post("/api/analyze/traffic", json=body).json()
    assert again["action"].startswith("Dropped")
    assert again["alert_id"] is None
    assert len(client.get("/api/alerts").json()) == 1


def test_normal_traffic_is_not_a_threat(client):
    body = {"source_ip": "10.0.0.5", "features": row_to_features(NORMAL_ROW)}
    res = client.post("/api/analyze/traffic", json=body).json()
    assert res["label"] == "Normal"
    assert res["is_threat"] is False
    assert res["alert_id"] is None


def test_missing_features_rejected(client):
    res = client.post("/api/analyze/traffic", json={"features": {"duration": 0}})
    assert res.status_code == 422


def test_invalid_ip_rejected(client):
    body = {"source_ip": "not-an-ip", "features": row_to_features(NORMAL_ROW)}
    assert client.post("/api/analyze/traffic", json=body).status_code == 422


def test_phishing_url_detected(client):
    res = client.post("/api/analyze/url",
                      json={"url": "paypal.com.verify-account-login.tk/webscr/signin.php"}).json()
    assert res["is_threat"] is True
    assert res["label"] == "Phishing"
    assert res["indicators"]["suspicious_word_count"] >= 2


def test_benign_url(client):
    res = client.post("/api/analyze/url", json={"url": "en.wikipedia.org/wiki/Computer_security"}).json()
    assert res["is_threat"] is False
    assert res["label"] == "Benign"


def test_stats_and_alert_status_update(client):
    client.post("/api/analyze/url", json={"url": "secure-bank-update.ml/login.php?acct=1"})
    stats = client.get("/api/stats").json()
    assert stats["total_events"] == 1
    assert stats["threats"] == 1
    alert_id = client.get("/api/alerts").json()[0]["id"]
    updated = client.patch(f"/api/alerts/{alert_id}", json={"status": "resolved"}).json()
    assert updated["status"] == "resolved"
    assert client.patch("/api/alerts/9999", json={"status": "resolved"}).status_code == 404


def test_manual_block_and_unblock(client):
    assert client.post("/api/blocklist", json={"ip": "203.0.113.50"}).status_code == 201
    assert client.post("/api/blocklist", json={"ip": "203.0.113.50"}).status_code == 409
    assert client.delete("/api/blocklist/203.0.113.50").status_code == 204
    assert client.delete("/api/blocklist/203.0.113.50").status_code == 404


def test_websocket_receives_alert(client):
    with client.websocket_connect("/ws/alerts") as ws:
        client.post("/api/analyze/url", json={"url": "free-bonus-wallet.xyz/download/setup.exe"})
        messages = [ws.receive_json(), ws.receive_json()]
    types = {m["type"] for m in messages}
    assert types == {"alert", "event"}
    alert = next(m for m in messages if m["type"] == "alert")["data"]
    assert alert["label"] == "Malware"
    assert alert["severity"] == "Critical"
