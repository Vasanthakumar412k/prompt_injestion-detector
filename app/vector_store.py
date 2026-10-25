"""Chroma access configured for explicit cosine embeddings."""
from __future__ import annotations

from app.config import settings

_client = None


def get_chroma_client():
    global _client
    if _client is None:
        import chromadb  # type: ignore

        _client = chromadb.PersistentClient(path=settings.chroma_persist_dir)
    return _client


def get_collection():
    collection = get_chroma_client().get_or_create_collection(
        name=settings.chroma_collection,
        metadata={"hnsw:space": "cosine"},
        embedding_function=None,
    )
    metadata = collection.metadata or {}
    space = metadata.get("hnsw:space", "l2")
    if space != "cosine":
        raise RuntimeError(
            f"Chroma collection '{settings.chroma_collection}' uses {space} distance; "
            "run `python scripts/reindex.py` to rebuild it with cosine distance."
        )
    return collection


def create_collection(name: str):
    return get_chroma_client().create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},
        embedding_function=None,
    )
