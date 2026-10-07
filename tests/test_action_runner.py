from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

RUNNER = Path(__file__).resolve().parents[1] / "scripts" / "action_runner.py"
SECRET = "AKIA1234567890ABCDEF"


@pytest.fixture
def action_env(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    temporary = tmp_path / "runner-temp"
    temporary.mkdir()
    output = tmp_path / "outputs"
    env = os.environ.copy()
    env.update(
        GITHUB_WORKSPACE=str(workspace),
        RUNNER_TEMP=str(temporary),
        GITHUB_OUTPUT=str(output),
        RUNNER_OS="Linux",
        INPUT_PATH=".",
        INPUT_FAIL_ON="high",
        INPUT_FAIL_ON_FINDINGS="true",
        INPUT_FAIL_ON_INCOMPLETE="true",
        INPUT_INCLUDE_HIDDEN="false",
        INPUT_ARTIFACT_NAME="sentinel-report",
        INPUT_RETENTION_DAYS="7",
        THRESHOLD_EXCEEDED="false",
    )
    return workspace, env


def invoke(env, phase="scan", cwd=None):
    return subprocess.run(
        [sys.executable, "-I", str(RUNNER), phase],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def outputs(env):
    return dict(
        line.split("=", 1)
        for line in Path(env["GITHUB_OUTPUT"]).read_text().splitlines()
    )


def test_redacted_reports_precede_gate_and_are_isolated(action_env):
    workspace, env = action_env
    target = workspace / "config.txt"
    target.write_text(f"AWS={SECRET}\n")
    first = invoke(env)
    assert first.returncode == 0, first.stderr
    first_outputs = outputs(env)
    report_dir = Path(first_outputs["reports-dir"])
    report = json.loads((report_dir / "secret-sentinel.json").read_text())
    assert first_outputs["finding-count"] == "1"
    assert first_outputs["credential-count"] == "1"
    assert first_outputs["complete"] == "true"
    assert first_outputs["scan-exit-code"] == "1"
    assert report_dir.is_relative_to(Path(env["RUNNER_TEMP"]))
    for path in report_dir.iterdir():
        assert SECRET not in path.read_text()
        assert str(workspace) not in path.read_text()
    assert SECRET not in first.stdout + first.stderr
    assert report
    gate = invoke({**env, "SCAN_EXIT_CODE": "1", "THRESHOLD_EXCEEDED": "true"}, "gate")
    assert gate.returncode == 1
    target.write_text("safe content\n")
    Path(env["GITHUB_OUTPUT"]).unlink()
    second = invoke(env)
    assert second.returncode == 0, second.stderr
    second_outputs = outputs(env)
    assert second_outputs["reports-dir"] != first_outputs["reports-dir"]
    assert second_outputs["finding-count"] == "0"
    assert (report_dir / "secret-sentinel.json").exists()


@pytest.mark.parametrize("input_path", ["../outside", "/etc", "missing"])
def test_target_outside_workspace_or_missing_is_rejected(action_env, input_path):
    _, env = action_env
    result = invoke({**env, "INPUT_PATH": input_path})
    assert result.returncode == 2
    assert not Path(env["GITHUB_OUTPUT"]).exists()


def test_symlink_target_is_rejected(action_env, tmp_path):
    workspace, env = action_env
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text(SECRET)
    (workspace / "link").symlink_to(outside, target_is_directory=True)
    result = invoke({**env, "INPUT_PATH": "link"})
    assert result.returncode == 2
    assert SECRET not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "name,value",
    [
        ("INPUT_FAIL_ON", "critical; touch hacked"),
        ("INPUT_FAIL_ON_FINDINGS", "yes"),
        ("INPUT_FAIL_ON_INCOMPLETE", "maybe"),
        ("INPUT_INCLUDE_HIDDEN", "1"),
        ("INPUT_ARTIFACT_NAME", "artifact\nforged-output=true"),
        ("INPUT_RETENTION_DAYS", "0"),
        ("INPUT_RETENTION_DAYS", "-1"),
        ("INPUT_RETENTION_DAYS", "abc"),
    ],
)
def test_invalid_inputs_fail_without_echoing_values(action_env, name, value):
    _, env = action_env
    result = invoke({**env, name: value})
    assert result.returncode == 2
    assert value not in result.stdout + result.stderr
    assert not Path(env["GITHUB_OUTPUT"]).exists()


def test_workspace_modules_and_hostile_path_are_never_executed(action_env):
    workspace, env = action_env
    marker = workspace / "executed"
    hostile = f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n"
    (workspace / "secret_sentinel.py").write_text(hostile)
    (workspace / "json.py").write_text(hostile)
    (workspace / "sitecustomize.py").write_text(hostile)
    target = workspace / "$(touch executed)"
    target.mkdir()
    (target / "secret.txt").write_text(SECRET)
    result = invoke(
        {**env, "INPUT_PATH": target.name, "PYTHONPATH": str(workspace)}, cwd=workspace
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert "::error::forged" not in result.stdout + result.stderr
    report_dir = Path(outputs(env)["reports-dir"])
    for path in report_dir.iterdir():
        text = path.read_text()
        assert SECRET not in text
        assert target.name not in text


def test_incomplete_scan_creates_reports_before_failure(action_env):
    workspace, env = action_env
    (workspace / "oversized.txt").write_bytes(b"x" * 2_000_001)
    result = invoke(env)
    assert result.returncode == 0, result.stderr
    values = outputs(env)
    assert values["complete"] == "false"
    assert values["scan-exit-code"] == "2"
    assert (Path(values["reports-dir"]) / "secret-sentinel.json").exists()
    assert invoke({**env, "SCAN_EXIT_CODE": "2"}, "gate").returncode == 2


@pytest.mark.parametrize(
    "code,findings,incomplete,expected",
    [
        (0, "true", "true", 0),
        (1, "true", "true", 1),
        (1, "false", "true", 0),
        (2, "false", "true", 2),
        (2, "true", "false", 0),
        (2, "false", "false", 0),
    ],
)
def test_gate_respects_separate_finding_and_completeness_controls(
    action_env, code, findings, incomplete, expected
):
    _, env = action_env
    result = invoke(
        {
            **env,
            "SCAN_EXIT_CODE": str(code),
            "THRESHOLD_EXCEEDED": "true" if code == 1 else "false",
            "INPUT_FAIL_ON_FINDINGS": findings,
            "INPUT_FAIL_ON_INCOMPLETE": incomplete,
        },
        "gate",
    )
    assert result.returncode == expected


def test_filename_secret_is_not_exported_in_reports(action_env):
    workspace, env = action_env
    private_name = "private-credential-7ca6f1de210947b5"
    (workspace / f"{private_name}.txt").write_text(f"AWS={SECRET}\n")
    result = invoke(env)
    assert result.returncode == 0, result.stderr
    report_dir = Path(outputs(env)["reports-dir"])
    for path in report_dir.iterdir():
        text = path.read_text()
        assert private_name not in text
        assert SECRET not in text
        assert "fingerprint" not in text
        assert "redacted_match" not in text
    assert private_name not in result.stdout + result.stderr


def test_control_characters_in_target_input_are_rejected(action_env):
    workspace, env = action_env
    target = workspace / "safe\n::error::forged"
    target.mkdir()
    result = invoke({**env, "INPUT_PATH": target.name})
    assert result.returncode == 2
    assert "::error::forged" not in result.stdout + result.stderr


def test_incomplete_opt_out_keeps_threshold_gate(action_env):
    workspace, env = action_env
    (workspace / "secret.txt").write_text(SECRET)
    (workspace / "oversized.txt").write_bytes(b"x" * 2_000_001)
    result = invoke(env)
    assert result.returncode == 0, result.stderr
    values = outputs(env)
    assert values["complete"] == "false"
    assert values["threshold-exceeded"] == "true"
    gated = invoke(
        {
            **env,
            "SCAN_EXIT_CODE": values["scan-exit-code"],
            "THRESHOLD_EXCEEDED": values["threshold-exceeded"],
            "INPUT_FAIL_ON_INCOMPLETE": "false",
        },
        "gate",
    )
    assert gated.returncode == 1


def test_report_directory_and_files_are_private(action_env):
    _, env = action_env
    result = invoke(env)
    assert result.returncode == 0, result.stderr
    directory = Path(outputs(env)["reports-dir"])
    assert directory.stat().st_mode & 0o777 == 0o700
    for report in directory.iterdir():
        assert report.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("status", ["", "3", "1\n::error::forged"])
def test_gate_rejects_invalid_scan_status(action_env, status):
    _, env = action_env
    result = invoke({**env, "SCAN_EXIT_CODE": status}, "gate")
    assert result.returncode == 2
    assert "::error::forged" not in result.stdout + result.stderr


def test_validated_target_replaced_by_symlink_never_reads_outside(
    action_env, tmp_path, monkeypatch
):
    import importlib.util

    specification = importlib.util.spec_from_file_location(
        "sentinel_action_runner", RUNNER
    )
    assert specification is not None and specification.loader is not None
    runner = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(runner)
    workspace, env = action_env
    target = workspace / "scan-target"
    target.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text(f"AWS={SECRET}\n")
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("INPUT_PATH", "scan-target")
    original_target_path = runner.target_path

    def swap_after_validation():
        validated = original_target_path()
        target.rmdir()
        target.symlink_to(outside, target_is_directory=True)
        return validated

    monkeypatch.setattr(runner, "target_path", swap_after_validation)
    assert runner.scan() == 0
    values = outputs(env)
    assert values["complete"] == "false"
    assert values["finding-count"] == "0"
    report = json.loads(
        (Path(values["reports-dir"]) / "secret-sentinel.json").read_text()
    )
    assert report["bytes_scanned"] == 0
    assert report["findings"] == []
    assert SECRET not in str(report)
