import os
from pathlib import Path

import pytest

from secret_sentinel.file_reader import (
    FileLimitExceeded,
    open_scan_root,
    read_scan_file,
)


def test_exact_read_and_overflow(tmp_path):
    (tmp_path / "input").write_bytes(b"safe")
    with open_scan_root(tmp_path) as descriptor:
        assert read_scan_file(descriptor, Path("input"), 4) == b"safe"
        with pytest.raises(FileLimitExceeded):
            read_scan_file(descriptor, Path("input"), 3)


@pytest.mark.parametrize("relative", [Path("../outside"), Path("/absolute"), Path(".")])
def test_rejects_invalid_relative_paths(tmp_path, relative):
    with open_scan_root(tmp_path) as descriptor, pytest.raises(OSError):
        read_scan_file(descriptor, relative, 10)


def test_rejects_leaf_and_ancestor_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"private")
    root = tmp_path / "root"
    root.mkdir()
    (root / "leaf").symlink_to(outside / "secret")
    (root / "ancestor").symlink_to(outside, target_is_directory=True)
    with open_scan_root(root) as descriptor:
        for relative in (Path("leaf"), Path("ancestor/secret")):
            with pytest.raises(OSError):
                read_scan_file(descriptor, relative, 100)


def test_pinned_root_survives_replacement(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "input").write_bytes(b"safe")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "input").write_bytes(b"private")
    with open_scan_root(root) as descriptor:
        root.rename(tmp_path / "saved")
        root.symlink_to(outside, target_is_directory=True)
        assert read_scan_file(descriptor, Path("input"), 100) == b"safe"
    with pytest.raises(OSError), open_scan_root(root):
        pass


def test_fifo_rejected_without_waiting(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    with open_scan_root(tmp_path) as descriptor, pytest.raises(OSError):
        read_scan_file(descriptor, Path("pipe"), 100)


def test_unsupported_platform_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "supports_dir_fd", set())
    with pytest.raises(OSError), open_scan_root(tmp_path):
        pass


def test_growth_after_fstat_is_bounded(tmp_path, monkeypatch):
    path = tmp_path / "input"
    path.write_bytes(b"a")
    original = os.fstat

    def grow(descriptor):
        metadata = original(descriptor)
        path.write_bytes(b"a" * 100)
        return metadata

    monkeypatch.setattr(os, "fstat", grow)
    with (
        open_scan_root(tmp_path) as descriptor,
        pytest.raises(FileLimitExceeded) as error,
    ):
        read_scan_file(descriptor, Path("input"), 4)
    assert error.value.consumed == 5
