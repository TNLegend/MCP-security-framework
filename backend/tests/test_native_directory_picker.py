from pathlib import Path

import pytest

import app.services.native_directory_picker as picker
from app.services.native_directory_picker import (
    NativeDirectoryPickerError,
    pick_native_local_directory,
)


def test_native_picker_returns_none_when_user_cancels(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        picker,
        "_show_native_directory_dialog",
        lambda **_: "",
    )
    assert pick_native_local_directory() is None


def test_native_picker_resolves_existing_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "mcp"
    source.mkdir()
    monkeypatch.setattr(
        picker,
        "_show_native_directory_dialog",
        lambda **_: str(source),
    )
    assert pick_native_local_directory() == source.resolve()


def test_native_picker_rejects_nonexistent_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing"
    monkeypatch.setattr(
        picker,
        "_show_native_directory_dialog",
        lambda **_: str(missing),
    )
    with pytest.raises(NativeDirectoryPickerError, match="selected_directory_unavailable"):
        pick_native_local_directory()
