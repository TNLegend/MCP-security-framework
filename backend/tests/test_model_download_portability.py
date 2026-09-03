from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from scripts import download_tool_analyzer_models as model_download


def test_model_download_uses_regular_file_snapshot_directories() -> None:
    calls: list[dict[str, object]] = []

    def fake_snapshot_download(**kwargs):  # noqa: ANN003,ANN202
        calls.append(kwargs)
        destination = Path(str(kwargs["local_dir"]))
        destination.mkdir(parents=True, exist_ok=True)
        return str(destination)

    with tempfile.TemporaryDirectory() as temporary:
        cache_dir = Path(temporary) / "models"
        with (
            patch("huggingface_hub.snapshot_download", side_effect=fake_snapshot_download),
            patch.object(
                sys,
                "argv",
                [
                    "download_tool_analyzer_models.py",
                    "--cache-dir",
                    str(cache_dir),
                ],
            ),
        ):
            assert model_download.main() == 0

    assert len(calls) == 2
    for call in calls:
        repo_id = str(call["repo_id"])
        revision = model_download.APPROVED_MODEL_REVISIONS[repo_id]
        destination = Path(str(call["local_dir"]))
        configured_cache = Path(str(call["cache_dir"]))

        assert destination.name == revision
        assert destination.parent.name == "snapshots"
        assert destination.parent.parent.name == "models--" + repo_id.replace("/", "--")
        assert configured_cache.name == "models"
