from __future__ import annotations

from d365fo_security_mcp.models.config import ServerConfig


def test_server_config_stale_threshold_days_default():
    config = ServerConfig()
    assert config.stale_threshold_days == 7


def test_server_config_stale_threshold_days_from_env(monkeypatch):
    monkeypatch.setenv("STALE_THRESHOLD_DAYS", "14")
    config = ServerConfig()
    assert config.stale_threshold_days == 14
