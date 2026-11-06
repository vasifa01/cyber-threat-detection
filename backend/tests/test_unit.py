"""Unit tests: feature extraction, label mapping, severity rules."""

import pytest

from app.ml import traffic, url_features
from app.services.response import AUTO_BLOCK_SEVERITIES, severity_for


class TestUrlFeatures:
    def test_detects_ip_host_and_https(self):
        f = url_features.extract("https://192.168.10.5/login")
        assert f["has_ip_host"] == 1
        assert f["has_https"] == 1
        assert f["suspicious_word_count"] >= 1

    def test_plain_domain_has_no_red_flags(self):
        f = url_features.extract("wikipedia.org")
        assert f["has_ip_host"] == 0
        assert f["suspicious_word_count"] == 0
        assert f["has_executable_ext"] == 0

    def test_feature_vector_matches_names(self):
        matrix = url_features.extract_matrix(["a.com", "b.org/x.exe"])
        assert len(matrix) == 2
        assert all(len(row) == len(url_features.FEATURE_NAMES) for row in matrix)

    @pytest.mark.parametrize("url,expected", [
        ("evil.ru/payload/update.exe", "Malware"),
        ("files.biz/app.apk", "Malware"),
        ("paypal-verify-account.tk/signin", "Phishing"),
    ])
    def test_malicious_subtype(self, url, expected):
        assert url_features.malicious_subtype(url) == expected

    def test_handles_garbage_input(self):
        assert url_features.extract("http://[::bad")["url_length"] > 0
        assert url_features.extract("")["url_length"] == 0


class TestTrafficMapping:
    @pytest.mark.parametrize("attack,category", [
        ("normal", "Normal"), ("neptune", "DoS"), ("smurf", "DoS"),
        ("nmap", "Probe"), ("guess_passwd", "R2L"), ("rootkit", "U2R"),
    ])
    def test_known_attacks(self, attack, category):
        assert traffic.to_category(attack) == category

    def test_feature_count_is_41(self):
        assert len(traffic.FEATURE_COLUMNS) == 41


class TestSeverity:
    def test_critical_and_high_trigger_auto_block(self):
        assert severity_for("U2R") == "Critical"
        assert severity_for("Phishing") == "High"
        assert {"High", "Critical"} == AUTO_BLOCK_SEVERITIES

    def test_probe_is_not_auto_blocked(self):
        assert severity_for("Probe") not in AUTO_BLOCK_SEVERITIES

    def test_benign_has_no_severity(self):
        assert severity_for("Normal") is None
        assert severity_for("Benign") is None
