from __future__ import annotations
from app.services.tda.configuration import EMBEDDING_MODEL_NAME
from app.services.tda.configuration import EMBEDDING_MODEL_VERSION
from app.services.tda.types import SemanticModelUnavailable
from app.services.tda.models.artifacts import _local_snapshot_path
from app.services.tda.models.artifacts import _sentence_transformer_version
from app.services.tda.text import _tokens
from pathlib import Path


class LocalEmbeddingModel:
    def __init__(
        self,
        model_name: str = EMBEDDING_MODEL_NAME,
        *,
        cache_dir: Path | None = None,
        pipeline=None,
    ) -> None:
        from app.core.runtime_paths import MODEL_CACHE_DIR

        self.pipeline = pipeline
        self.model_name = model_name
        self.cache_dir = cache_dir or MODEL_CACHE_DIR
        self.model_version = (
            pipeline.model_versions["embedding"]["version"]
            if pipeline
            else EMBEDDING_MODEL_VERSION
        )
        self._model = None

    def similarity(self, previous_text: str, current_text: str) -> float:
        model = self._load_model()
        embeddings = model.encode(
            [f"query: {previous_text}", f"passage: {current_text}"],
            normalize_embeddings=True,
        )
        return float(sum((a * b for a, b in zip(embeddings[0], embeddings[1]))))

    def _load_model(self):
        from pathlib import Path
        from app.core.runtime_paths import configure_runtime_environment

        if self._model is not None:
            return self._model
        configure_runtime_environment()
        if self.pipeline:
            if self.model_name != self.pipeline.model_versions["embedding"]["name"]:
                raise SemanticModelUnavailable("pipeline_model_name_mismatch")
            self.pipeline.verify()
            model_ref = self.pipeline.model_path("embedding")
        else:
            model_ref = _local_snapshot_path(self.cache_dir, self.model_name)
            if model_ref is None:
                model_ref = Path(self.model_name)
        try:
            from sentence_transformers import SentenceTransformer
        except Exception as exc:
            raise SemanticModelUnavailable(
                "embedding_model_dependency_unavailable"
            ) from exc
        try:
            self._model = SentenceTransformer(
                str(model_ref),
                cache_folder=str(self.cache_dir),
                local_files_only=True,
                trust_remote_code=False,
            )
            self.observed_model_version = _sentence_transformer_version(
                self._model, EMBEDDING_MODEL_VERSION
            )
            if self.pipeline:
                self.pipeline.verify()
            else:
                self.model_version = self.observed_model_version
        except Exception as exc:
            self._model = None
            raise SemanticModelUnavailable("embedding_model_unavailable") from exc
        return self._model


class HashingEmbeddingModel:
    """Deterministic local fallback for tests and reports; not used for final decisions."""

    def similarity(self, previous_text: str, current_text: str) -> float:
        left = set(_tokens(previous_text))
        right = set(_tokens(current_text))
        if not left and (not right):
            return 1.0
        if not left or not right:
            return 0.0
        return len(left & right) / len(left | right)
