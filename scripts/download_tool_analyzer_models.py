import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.services.tda.configuration import EMBEDDING_MODEL_NAME
from app.core.runtime_paths import MODEL_CACHE_DIR
from app.core.runtime_paths import configure_runtime_environment  # noqa: E402

ALLOW_PATTERNS = [
    "*.json",
    "*.txt",
    "*.model",
    "model.safetensors",
    "modules.json",
    "sentence_bert_config.json",
    "1_Pooling/*",
]

IGNORE_PATTERNS = [
    "*.h5",
    "*.onnx",
    "*.ot",
    "*.msgpack",
    "onnx/*",
    "openvino/*",
    "tf_model.*",
    "flax_model.*",
    "rust_model.*",
]

APPROVED_MODEL_REVISIONS = {
    EMBEDDING_MODEL_NAME: "614241f622f53c4eeff9890bdc4f31cfecc418b3",
}


def portable_snapshot_directory(cache_dir: Path, repo_id: str, revision: str) -> Path:
    """Return the regular-file snapshot path used by the project on all platforms.

    Hugging Face's shared cache layout relies on symlinks. Standard Windows users
    may not have the Create symbolic links privilege, so setup downloads directly
    into the snapshot directory that the analyzer already resolves locally.
    """
    model_dir = cache_dir / ("models--" + repo_id.replace("/", "--"))
    return model_dir / "snapshots" / revision


def main() -> int:
    configure_runtime_environment()
    parser = argparse.ArgumentParser(
        description="Download the M6 E5 drift model only. M4 GLiNER/DeBERTa weights are separately installed from pinned public revisions and SHA-256 verified; no owner signature is needed."
    )
    parser.add_argument(
        "--cache-dir",
        default=str(MODEL_CACHE_DIR),
        help="Project-local Hugging Face model cache directory under .runtime.",
    )
    args = parser.parse_args()

    try:
        from huggingface_hub import snapshot_download
    except Exception as exc:
        raise SystemExit(
            "huggingface-hub is required. Install backend requirements first."
        ) from exc

    cache_dir = Path(args.cache_dir).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    downloads = []
    for repo_id in [EMBEDDING_MODEL_NAME]:
        revision = APPROVED_MODEL_REVISIONS[repo_id]
        destination = portable_snapshot_directory(cache_dir, repo_id, revision)
        destination.mkdir(parents=True, exist_ok=True)
        snapshot_path = Path(
            snapshot_download(
                repo_id=repo_id,
                revision=revision,
                cache_dir=str(cache_dir),
                local_dir=str(destination),
                local_files_only=False,
                resume_download=True,
                allow_patterns=ALLOW_PATTERNS,
                ignore_patterns=IGNORE_PATTERNS,
            )
        )
        downloads.append(
            {
                "repo_id": repo_id,
                "cache_dir": str(cache_dir),
                "snapshot_path": str(snapshot_path),
                "revision": snapshot_path.name,
            }
        )

    print(json.dumps({"downloaded": downloads}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
