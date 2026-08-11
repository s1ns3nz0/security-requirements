import copy
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "security-requirements"
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import confirmation  # noqa: E402
import runtime_paths  # noqa: E402


def profile():
    return {
        "version": "0.1.0",
        "locale": "en",
        "inferred": {"csp": "aws", "deployment_model": "serverless"},
        "declared": {"data_types": [{"id": "basic_contact"}]},
        "derived": {"baseline": "nist-800-53b-moderate"},
    }


def test_stamp_binds_confirmation_to_exact_profile():
    original = profile()
    stamped = confirmation.stamp(copy.deepcopy(original), "user", "2026-07-31T10:00:00Z")

    assert stamped["confirmation"] == {
        "status": "confirmed",
        "confirmed_by": "user",
        "confirmed_at": "2026-07-31T10:00:00Z",
        "profile_digest": confirmation.profile_digest(original),
    }
    assert confirmation.validate(stamped, stamped["confirmation"]) == []


def test_profile_change_invalidates_confirmation():
    stamped = confirmation.stamp(profile(), "user", "2026-07-31T10:00:00Z")
    stamped["declared"]["data_types"].append({"id": "payment_card"})

    assert confirmation.validate(stamped, stamped["confirmation"]) == [
        "profile changed after confirmation; run the confirmation gate again"
    ]


def test_missing_confirmation_is_rejected():
    assert confirmation.validate(profile(), None) == [
        "plugin-owned confirmation state is missing"
    ]


def test_neutral_data_root_precedes_legacy_claude_root(tmp_path, monkeypatch):
    neutral = tmp_path / "neutral"
    legacy = tmp_path / "legacy"
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(neutral))
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(legacy))

    assert runtime_paths.plugin_data_root() == neutral


def test_default_data_root_is_external_and_stable(tmp_path, monkeypatch):
    monkeypatch.delenv("SECURITY_REQUIREMENTS_DATA", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    expected = tmp_path / "state" / "security-requirements" / "v1"

    assert runtime_paths.plugin_data_root(platform="linux") == expected
    assert runtime_paths.plugin_data_root(platform="linux") == expected
    assert not expected.exists()


def test_runtime_paths_cli_prints_resolved_external_default(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    state_home = tmp_path / "state" / ".." / "external-state"
    env = os.environ.copy()
    env.pop("SECURITY_REQUIREMENTS_DATA", None)
    env.pop("CLAUDE_PLUGIN_DATA", None)
    env["HOME"] = str(home)
    if sys.platform.startswith("win"):
        env["LOCALAPPDATA"] = str(state_home)
        expected = state_home / "security-requirements" / "v1"
    elif sys.platform == "darwin":
        expected = (
            home
            / "Library"
            / "Application Support"
            / "security-requirements"
            / "v1"
        )
    else:
        env["XDG_STATE_HOME"] = str(state_home)
        expected = state_home / "security-requirements" / "v1"
    expected = expected.resolve()

    result = subprocess.run(
        [sys.executable, str(PLUGIN_ROOT / "scripts" / "runtime_paths.py")],
        cwd=project,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert Path(result.stdout.strip()) == expected
    assert expected.is_absolute()
    assert not expected.is_relative_to(project)


def test_macos_data_root_uses_application_support(tmp_path, monkeypatch):
    monkeypatch.delenv("SECURITY_REQUIREMENTS_DATA", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setattr(runtime_paths.Path, "home", lambda: tmp_path)

    assert runtime_paths.plugin_data_root(platform="darwin") == (
        tmp_path / "Library" / "Application Support" / "security-requirements" / "v1"
    )


def test_windows_data_root_uses_local_app_data(tmp_path, monkeypatch):
    monkeypatch.delenv("SECURITY_REQUIREMENTS_DATA", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    local_app_data = tmp_path / "AppData" / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))

    assert runtime_paths.plugin_data_root(platform="win32") == (
        local_app_data / "security-requirements" / "v1"
    )


@pytest.mark.parametrize("variable", ["SECURITY_REQUIREMENTS_DATA", "CLAUDE_PLUGIN_DATA"])
def test_relative_explicit_data_root_is_rejected_outside_project_cwd(
    tmp_path, monkeypatch, variable
):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.delenv("SECURITY_REQUIREMENTS_DATA", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setenv(variable, "plugin-state")

    with pytest.raises(ValueError, match=rf"{variable} must be an absolute path"):
        runtime_paths.plugin_data_root()


@pytest.mark.parametrize(
    ("platform", "variable", "expected_parts"),
    [
        ("linux", "XDG_STATE_HOME", (".local", "state")),
        ("win32", "LOCALAPPDATA", ("AppData", "Local")),
    ],
)
def test_relative_os_state_root_falls_back_outside_project_cwd(
    tmp_path, monkeypatch, platform, variable, expected_parts
):
    project = tmp_path / "project"
    home = tmp_path / "home"
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.delenv("SECURITY_REQUIREMENTS_DATA", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setenv(variable, "state")
    monkeypatch.setattr(runtime_paths.Path, "home", lambda: home)

    root = runtime_paths.plugin_data_root(platform=platform)

    assert root == home.joinpath(*expected_parts, "security-requirements", "v1")
    assert root.is_absolute()
    assert not root.is_relative_to(project)


def test_confirmation_does_not_write_state_for_relative_explicit_root(tmp_path, monkeypatch):
    project = tmp_path / "project"
    path = project / ".security-requirements" / "profile.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump(profile()), encoding="utf-8")
    monkeypatch.chdir(project)
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", "plugin-state")

    assert confirmation.main(["--stamp", str(path), "--by", "user"]) == 1
    assert not (project / "plugin-state").exists()


def test_cli_check_rejects_unconfirmed_profile(tmp_path, monkeypatch):
    path = tmp_path / "profile.yaml"
    path.write_text(yaml.safe_dump(profile()), encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "plugin-data"))

    assert confirmation.main(["--check", str(path)]) == 1


def test_repository_cannot_forge_plugin_owned_approval(tmp_path, monkeypatch):
    path = tmp_path / "project" / ".security-requirements" / "profile.yaml"
    path.parent.mkdir(parents=True)
    forged = confirmation.stamp(profile(), "user", "2026-07-31T10:00:00Z")
    path.write_text(yaml.safe_dump(forged), encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "plugin-data"))

    assert confirmation.main(["--check", str(path)]) == 1


def test_cli_stamp_writes_authoritative_state_outside_repository(tmp_path, monkeypatch):
    path = tmp_path / "project" / ".security-requirements" / "profile.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump(profile()), encoding="utf-8")
    data = tmp_path / "plugin-data"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data))

    assert confirmation.main(["--stamp", str(path), "--by", "user"]) == 0
    assert confirmation.main(["--check", str(path)]) == 0
    states = list((data / "confirmations").glob("*.yaml"))
    assert len(states) == 1
    assert not str(states[0]).startswith(str(path.parent.parent))


def test_cli_stamp_and_check_use_neutral_data_root(tmp_path, monkeypatch):
    path = tmp_path / "project" / ".security-requirements" / "profile.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump(profile()), encoding="utf-8")
    neutral = tmp_path / "neutral"
    legacy = tmp_path / "legacy"
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(neutral))
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(legacy))

    assert confirmation.main(["--stamp", str(path), "--by", "user"]) == 0
    assert confirmation.main(["--check", str(path)]) == 0
    assert list((neutral / "confirmations").glob("*.yaml"))
    assert not legacy.exists()


def test_cli_stamp_and_check_use_default_data_root(tmp_path, monkeypatch):
    path = tmp_path / "project" / ".security-requirements" / "profile.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump(profile()), encoding="utf-8")
    state_home = tmp_path / "state"
    monkeypatch.delenv("SECURITY_REQUIREMENTS_DATA", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
    monkeypatch.setattr(runtime_paths.sys, "platform", "linux")

    assert confirmation.main(["--stamp", str(path), "--by", "user"]) == 0
    assert confirmation.main(["--check", str(path)]) == 0
    assert list((state_home / "security-requirements" / "v1" / "confirmations").glob("*.yaml"))
