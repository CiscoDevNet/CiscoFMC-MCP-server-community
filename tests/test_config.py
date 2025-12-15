from sfw_mcp_fmc.config import FMCSettings


def test_from_mapping_parses_and_normalizes():
    cfg = {
        "FMC_BASE_URL": "https://example.local/api/",
        "FMC_USERNAME": "admin",
        "FMC_PASSWORD": "secret",
        "FMC_VERIFY_SSL": "TrUe",
        "FMC_TIMEOUT": "45",
        "FMC_DOMAIN_UUID": "abc-123",
    }

    settings = FMCSettings.from_mapping(cfg)

    assert settings.base_url == "https://example.local/api"
    assert settings.username == "admin"
    assert settings.password == "secret"
    assert settings.verify_ssl is True
    assert settings.timeout == 45.0
    assert settings.domain_uuid == "abc-123"


def test_from_mapping_raises_on_missing_required_fields():
    cfg = {"FMC_USERNAME": "user"}

    try:
        FMCSettings.from_mapping(cfg)
    except ValueError as exc:
        assert "FMC_BASE_URL" in str(exc)
    else:
        raise AssertionError("Expected ValueError for missing settings")
