import pytest

from ssdf_pubmetrics.config import Config, ConfigError, load_config


def test_load_config_requires_password(monkeypatch):
    monkeypatch.delenv("CH_PASSWORD", raising=False)
    monkeypatch.setenv("PUBLIC_PSEUDONYM_KEY", "00112233445566778899aabbccddeeff")
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_requires_key(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.delenv("PUBLIC_PSEUDONYM_KEY", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_rejects_non_hex_key(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("PUBLIC_PSEUDONYM_KEY", "not-hex")
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_defaults(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("PUBLIC_PSEUDONYM_KEY", "00112233445566778899aabbccddeeff")
    cfg = load_config()
    assert isinstance(cfg, Config)
    assert cfg.ch_user == "ssdf_pubmetrics"
    assert cfg.bucket_secs == 300
    assert cfg.lookback_hours == 1
    assert cfg.baseline_days == 30
    assert cfg.top_n == 20
    assert cfg.key_version == 1
    assert cfg.pseudonym_key == bytes.fromhex("00112233445566778899aabbccddeeff")
