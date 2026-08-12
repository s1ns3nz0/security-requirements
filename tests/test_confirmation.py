import copy
import hashlib
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


def test_external_neutral_root_wins_even_when_legacy_root_is_project_contained(
    tmp_path,
):
    project = tmp_path / "project"
    project.mkdir()
    neutral = tmp_path / "neutral-state"
    legacy = project / "legacy-state"

    assert runtime_paths.plugin_data_root(
        env={
            "SECURITY_REQUIREMENTS_DATA": str(neutral),
            "CLAUDE_PLUGIN_DATA": str(legacy),
        },
        project_root=project,
    ) == neutral.resolve()


@pytest.mark.parametrize("variable", ["SECURITY_REQUIREMENTS_DATA", "CLAUDE_PLUGIN_DATA"])
def test_explicit_state_root_inside_inspected_project_is_rejected(tmp_path, variable):
    project = tmp_path / "project"
    project.mkdir()
    env = {variable: str(project / "plugin-state")}

    with pytest.raises(ValueError, match="must be outside the inspected project"):
        runtime_paths.plugin_data_root(env=env, project_root=project)

    assert not (project / "plugin-state").exists()


def test_physical_project_containment_matches_an_existing_alias_ancestor(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    alias = tmp_path / "external-alias"
    project.mkdir()
    alias.mkdir()
    candidate = alias / "not-created" / "state.yaml"
    real_samefile = os.path.samefile

    def samefile(left, right):
        if Path(left) == alias and Path(right) == project:
            return True
        return real_samefile(left, right)

    monkeypatch.setattr(runtime_paths.os.path, "samefile", samefile)

    assert runtime_paths.path_is_within_project(candidate, project)


def test_physical_project_containment_handles_samefile_oserror(tmp_path, monkeypatch):
    project = tmp_path / "project"
    external = tmp_path / "external"
    project.mkdir()
    external.mkdir()

    def unavailable(_left, _right):
        raise OSError("samefile unavailable")

    monkeypatch.setattr(runtime_paths.os.path, "samefile", unavailable)

    assert not runtime_paths.path_is_within_project(
        external / "not-created" / "state.yaml", project
    )


def test_case_variant_siblings_remain_distinct_on_a_case_sensitive_filesystem(
    tmp_path,
):
    project = tmp_path / "Repo"
    sibling = tmp_path / "rEPO"
    project.mkdir()
    if sibling.exists() and os.path.samefile(project, sibling):
        pytest.skip("temporary filesystem is case-insensitive")
    sibling.mkdir()

    assert not runtime_paths.path_is_within_project(sibling / "state", project)


def test_case_insensitive_project_alias_cannot_hold_plugin_state(tmp_path):
    if sys.platform != "darwin":
        pytest.skip("requires macOS filesystem alias semantics")
    project = tmp_path / "Repo"
    project.mkdir()
    alias = tmp_path / "rEPO"
    try:
        same_directory = alias.exists() and os.path.samefile(project, alias)
    except OSError:
        same_directory = False
    if not same_directory:
        pytest.skip("temporary filesystem is case-sensitive")

    with pytest.raises(ValueError, match="must be outside the inspected project"):
        runtime_paths.plugin_data_root(
            env={"SECURITY_REQUIREMENTS_DATA": str(alias / "state")},
            project_root=project,
        )


def test_project_owned_state_symlink_cannot_redirect_authoritative_state(tmp_path):
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    link = project / "state-link"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="must be outside the inspected project"):
        runtime_paths.plugin_data_root(
            env={"SECURITY_REQUIREMENTS_DATA": str(link)}, project_root=project
        )


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
        [sys.executable, "-I", str(PLUGIN_ROOT / "scripts" / "runtime_paths.py")],
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


def test_runtime_paths_cli_rejects_state_inside_explicit_project(tmp_path):
    project = tmp_path / "project with spaces 한글"
    project.mkdir()
    env = os.environ.copy()
    env["SECURITY_REQUIREMENTS_DATA"] = str(project / "state")
    env.pop("CLAUDE_PLUGIN_DATA", None)

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "runtime_paths.py"),
            "--project-root",
            str(project),
        ],
        cwd=project,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "must be outside the inspected project" in result.stderr
    assert result.stdout == ""


def test_runtime_paths_cli_treats_cwd_as_the_inspected_project(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    env = os.environ.copy()
    env["SECURITY_REQUIREMENTS_DATA"] = str(project / "state")
    env.pop("CLAUDE_PLUGIN_DATA", None)

    result = subprocess.run(
        [sys.executable, "-I", str(PLUGIN_ROOT / "scripts" / "runtime_paths.py")],
        cwd=project,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "must be outside the inspected project" in result.stderr
    assert result.stdout == ""


def test_runtime_bootstrap_rejects_python_older_than_3_12(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runtime_paths.sys, "version_info", (3, 11, 9))

    assert runtime_paths.main([]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "requires Python 3.12 or newer" in captured.err


def test_selected_skill_owns_plugin_root_and_ambient_root_cannot_redirect_it(tmp_path):
    selected = (
        PLUGIN_ROOT / "skills" / "deriving-security-requirements" / "SKILL.md"
    )

    assert runtime_paths.plugin_root_from_skill(selected) == PLUGIN_ROOT.resolve()
    assert runtime_paths.plugin_root_from_skill(
        selected, ambient_root=PLUGIN_ROOT
    ) == PLUGIN_ROOT.resolve()
    with pytest.raises(ValueError, match="ambient plugin root does not match"):
        runtime_paths.plugin_root_from_skill(
            selected, ambient_root=tmp_path / "counterfeit-plugin"
        )

    alias = tmp_path / "payload-alias"
    alias.symlink_to(PLUGIN_ROOT, target_is_directory=True)
    with pytest.raises(ValueError, match="ambient plugin root does not match"):
        runtime_paths.plugin_root_from_skill(selected, ambient_root=alias)


def test_runtime_paths_cli_resolves_selected_skill_and_rejects_ambient_redirect(tmp_path):
    selected = (
        PLUGIN_ROOT / "skills" / "security-requirements-init" / "SKILL.md"
    )
    command = [
        sys.executable,
        "-I",
        str(PLUGIN_ROOT / "scripts" / "runtime_paths.py"),
        "--skill",
        str(selected),
    ]

    resolved = subprocess.run(command, capture_output=True, text=True, check=False)
    redirected = subprocess.run(
        [*command, "--ambient-root", str(tmp_path / "counterfeit")],
        capture_output=True,
        text=True,
        check=False,
    )

    assert resolved.returncode == 0
    assert Path(resolved.stdout.strip()) == PLUGIN_ROOT.resolve()
    assert redirected.returncode == 1
    assert "ambient plugin root does not match" in redirected.stderr
    assert redirected.stdout == ""


def test_runtime_paths_cli_rejects_ambient_root_environment_redirect(tmp_path):
    selected = (
        PLUGIN_ROOT / "skills" / "deriving-security-requirements" / "SKILL.md"
    )
    env = os.environ.copy()
    env["SECURITY_REQUIREMENTS_ROOT"] = str(tmp_path / "counterfeit")

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PLUGIN_ROOT / "scripts" / "runtime_paths.py"),
            "--skill",
            str(selected),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "ambient plugin root does not match" in result.stderr
    assert result.stdout == ""


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


def test_confirmation_rejects_absolute_authoritative_state_inside_project(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    path = project / ".security-requirements" / "profile.yaml"
    path.parent.mkdir(parents=True)
    original = yaml.safe_dump(profile())
    path.write_text(original, encoding="utf-8")
    state = project / "plugin-state"
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(state))

    assert confirmation.main(["--stamp", str(path), "--by", "user"]) == 1
    assert path.read_text(encoding="utf-8") == original
    assert not state.exists()


def test_confirmation_stamp_rejects_final_state_artifact_inside_project(
    tmp_path, monkeypatch, capsys
):
    state_root = tmp_path / "data-root"
    project = state_root / "confirmations"
    path = project / ".security-requirements" / "profile.yaml"
    path.parent.mkdir(parents=True)
    original = yaml.safe_dump(profile())
    path.write_text(original, encoding="utf-8")
    key = hashlib.sha256(str(project.resolve()).encode("utf-8")).hexdigest()
    authority = project / f"{key}.yaml"
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(state_root))

    assert confirmation.main(["--stamp", str(path), "--by", "user"]) == 1

    assert "confirmation state must remain outside the project" in capsys.readouterr().err
    assert path.read_text(encoding="utf-8") == original
    assert not authority.exists()


def test_confirmation_check_rejects_matching_forged_state_inside_project(
    tmp_path, monkeypatch, capsys
):
    state_root = tmp_path / "data-root"
    project = state_root / "confirmations"
    path = project / ".security-requirements" / "profile.yaml"
    path.parent.mkdir(parents=True)
    forged = confirmation.stamp(profile(), "attacker", "2026-08-12T00:00:00Z")
    path.write_text(yaml.safe_dump(forged), encoding="utf-8")
    key = hashlib.sha256(str(project.resolve()).encode("utf-8")).hexdigest()
    authority = project / f"{key}.yaml"
    authority.write_text(yaml.safe_dump(forged["confirmation"]), encoding="utf-8")
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(state_root))

    assert confirmation.main(["--check", str(path)]) == 1

    assert "confirmation state must remain outside the project" in capsys.readouterr().err


def test_confirmation_rejects_a_physically_project_owned_final_authority(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    profile_path = project / ".security-requirements" / "profile.yaml"
    profile_path.parent.mkdir(parents=True)
    state_root = tmp_path / "external-state"
    confirmations = state_root / "confirmations"
    confirmations.mkdir(parents=True)
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(state_root))
    real_samefile = os.path.samefile

    def samefile(left, right):
        if Path(left) == confirmations and Path(right) == project:
            return True
        return real_samefile(left, right)

    monkeypatch.setattr(runtime_paths.os.path, "samefile", samefile)

    with pytest.raises(
        ValueError, match="confirmation state must remain outside the project"
    ):
        confirmation.confirmation_state_path(profile_path)


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


def test_confirmation_survives_separate_calls_only_when_each_binds_the_exact_state_root(
    tmp_path,
):
    project = tmp_path / "project with spaces 한글"
    profile_path = project / ".security-requirements" / "profile.yaml"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text(yaml.safe_dump(profile()), encoding="utf-8")
    state_root = tmp_path / "authoritative state"
    default_state = tmp_path / "unused-default-state"
    base_env = os.environ.copy()
    base_env.pop("CLAUDE_PLUGIN_DATA", None)
    base_env["XDG_STATE_HOME"] = str(default_state)
    command = [
        sys.executable,
        "-I",
        str(PLUGIN_ROOT / "scripts" / "confirmation.py"),
    ]

    stamp_env = {**base_env, "SECURITY_REQUIREMENTS_DATA": str(state_root)}
    stamp = subprocess.run(
        [*command, "--stamp", str(profile_path), "--by", "user"],
        cwd=project,
        env=stamp_env,
        capture_output=True,
        text=True,
        check=False,
    )
    unbound = subprocess.run(
        [*command, "--check", str(profile_path)],
        cwd=project,
        env=base_env,
        capture_output=True,
        text=True,
        check=False,
    )
    check_env = {**base_env, "SECURITY_REQUIREMENTS_DATA": str(state_root)}
    rebound = subprocess.run(
        [*command, "--check", str(profile_path)],
        cwd=project,
        env=check_env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert stamp.returncode == 0, stamp.stderr
    assert unbound.returncode == 1
    assert "plugin-owned confirmation state is missing" in unbound.stderr
    assert rebound.returncode == 0, rebound.stderr
    assert list((state_root / "confirmations").glob("*.yaml"))
    assert not default_state.exists()


@pytest.mark.parametrize("symlink_kind", ["profile", "state-ancestor"])
def test_confirmation_preflights_profile_and_state_before_writing(
    tmp_path, monkeypatch, symlink_kind
):
    project = tmp_path / "project"
    state_root = tmp_path / "plugin-data"
    outside = tmp_path / "outside"
    state_dir = project / ".security-requirements"
    state_dir.mkdir(parents=True)
    state_root.mkdir()
    outside.mkdir()
    path = state_dir / "profile.yaml"
    if symlink_kind == "profile":
        victim = outside / "profile.yaml"
        victim.write_text(yaml.safe_dump(profile()), encoding="utf-8")
        path.symlink_to(victim)
    else:
        path.write_text(yaml.safe_dump(profile()), encoding="utf-8")
        (state_root / "confirmations").symlink_to(outside, target_is_directory=True)
        victim = path
    before = victim.read_bytes()
    monkeypatch.setenv("SECURITY_REQUIREMENTS_DATA", str(state_root))

    assert confirmation.main(["--stamp", str(path), "--by", "user"]) == 1
    assert victim.read_bytes() == before
    assert list(outside.iterdir()) == ([victim] if symlink_kind == "profile" else [])
