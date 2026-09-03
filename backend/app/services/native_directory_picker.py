from __future__ import annotations

from pathlib import Path


class NativeDirectoryPickerError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _show_native_directory_dialog(*, initial_directory: Path | None) -> str:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError as exc:
        raise NativeDirectoryPickerError("native_directory_picker_unavailable") from exc

    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except tk.TclError:
            pass
        root.update_idletasks()
        selected = filedialog.askdirectory(
            parent=root,
            initialdir=str(initial_directory) if initial_directory else None,
            mustexist=True,
            title="Select MCP source directory",
        )
        return str(selected or "")
    except Exception as exc:
        raise NativeDirectoryPickerError("native_directory_picker_failed") from exc
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass


def pick_native_local_directory(
    *,
    initial_directory: Path | None = None,
) -> Path | None:
    selected = _show_native_directory_dialog(initial_directory=initial_directory).strip()
    if not selected:
        return None

    candidate = Path(selected).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise NativeDirectoryPickerError("selected_directory_unavailable") from exc
    if not resolved.is_dir():
        raise NativeDirectoryPickerError("selected_path_not_directory")
    return resolved
