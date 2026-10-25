"""Offline sentence-transformer loading and embedding helpers."""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Sequence

from app.config import settings

logger = logging.getLogger(__name__)


def _model_reference(configured_path: str, model_id: str) -> str:
    path = Path(configured_path).expanduser()
    if path.is_dir():
        return str(path)
    if configured_path and path != Path(model_id):
        logger.info("Configured model directory is not present: %s; checking local HF cache", path)
    return model_id


@lru_cache(maxsize=1)
def get_embedding_model():
    """Load the embedding model from disk or the Hugging Face cache only."""
    from sentence_transformers import SentenceTransformer

    model_id = settings.embedding_model
    reference = _model_reference(settings.embedding_model_path, model_id)
    try:
        model = SentenceTransformer(reference, local_files_only=True)
    except Exception as exc:
        message = (
            "The local embedding model is unavailable. Run "
            "`python scripts/download_models.py` before starting the app."
        )
        raise RuntimeError(message) from exc
    logger.info(
        "Loaded local embedding model reference=%s max_seq_length=%d",
        reference,
        model.max_seq_length,
    )
    return model


def encode_texts(texts: Sequence[str]) -> list[list[float]]:
    """Encode text using normalized vectors for cosine retrieval."""
    if not texts:
        return []
    vectors = get_embedding_model().encode(
        list(texts),
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=False,
    )
    return vectors.tolist()


def get_embedding_tokenizer():
    return get_embedding_model().tokenizer
