from pathlib import Path

import pytest

from sfw_mcp_fmc.profile_registry import FMCProfileRegistry


def _write_profile(path: Path, name: str, extra: str = "") -> None:
    content = f"""FMC_PROFILE_ID={name}
FMC_PROFILE_DISPLAY_NAME={name.title()}
FMC_PROFILE_ALIASES={name},alias-{name}
FMC_BASE_URL=https://{name}.example.com
FMC_USERNAME=admin
FMC_PASSWORD=pass
{extra}
"""
    (path / f"{name}.env").write_text(content)


def test_registry_loads_profiles_and_resolves_alias(tmp_path: Path):
    _write_profile(tmp_path, "fmc-alpha")
    _write_profile(tmp_path, "fmc-beta")

    registry = FMCProfileRegistry.from_directory(str(tmp_path), default_profile_id="fmc-beta")

    profiles = registry.list_profiles()
    assert {p.profile_id for p in profiles} == {"fmc-alpha", "fmc-beta"}
    assert registry.default_profile_id == "fmc-beta"

    resolved = registry.resolve("alias-fmc-alpha")
    assert resolved.profile_id == "fmc-alpha"
    assert resolved.settings.base_url == "https://fmc-alpha.example.com"


def test_registry_missing_dir(tmp_path: Path):
    missing = tmp_path / "nope"
    with pytest.raises(ValueError):
        FMCProfileRegistry.from_directory(str(missing))
