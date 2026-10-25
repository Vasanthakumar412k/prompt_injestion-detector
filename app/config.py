"""
config.py – Central settings for the Security-First RAG Platform.
All values can be overridden via environment variables.
"""
from __future__ import annotations

import os
from dotenv import load_dotenv

# Load .env into os.environ early so SDKs find their keys
load_dotenv()

# Disable ChromaDB telemetry before chromadb is imported anywhere
os.environ["ANONYMIZED_TELEMETRY"] = "False"
try:
    import posthog
    posthog.capture = lambda *args, **kwargs: None
except Exception:
    pass

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Database ───────────────────────────────────────────────────────────
    database_url: str = "sqlite:///./rag_platform.db"
    chroma_persist_dir: str = "./chroma_db"

    # ── JWT ────────────────────────────────────────────────────────────────
    jwt_secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # ── Embedding model ────────────────────────────────────────────────────
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_model_path: str = "./models/all-MiniLM-L6-v2"
    chroma_collection: str = "rag_chunks"

    # ── Chunking ───────────────────────────────────────────────────────────
    chunk_size_tokens: int = 200
    chunk_overlap_tokens: int = 30
    retrieval_top_k: int = 5
    min_similarity: float = 0.45
    relative_cutoff: float = 0.82
    max_context_chars: int = 12000
    chat_context_turns: int = 10
    conversation_retention_days: int = 365

    # ── DeBERTa detector ───────────────────────────────────────────────────
    deberta_model: str = "protectai/deberta-v3-base-prompt-injection-v2"
    deberta_model_path: str = "./models/deberta-v3-base-prompt-injection-v2"
    deberta_threshold: float = 0.5

    # ── Prompt Guard (Groq) ────────────────────────────────────────────────
    promptguard_model: str = "meta-llama/llama-prompt-guard-2-86m"
    promptguard_threshold: float = 0.1

    # ── Gemini judge ───────────────────────────────────────────────────────
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")

    # ── Chat LLMs (Groq) ──────────────────────────────────────────────────
    groq_model_large: str = "openai/gpt-oss-120b"
    groq_model_medium: str = "openai/gpt-oss-20b"
    groq_model_qwen: str = "qwen/qwen3.8-27b"

    # ── Ensemble failure behaviour ─────────────────────────────────────────
    # For user prompts: True = fail open (allow + log), False = fail closed
    user_prompt_fail_open: bool = True
    # For retrieved documents: always fail closed (quarantine) – not configurable
    # but exposed here for documentation purposes
    doc_fail_closed: bool = True

    # ── Output guard ───────────────────────────────────────────────────────
    output_guard_ngram_threshold: float = 0.15   # Jaccard overlap threshold
    output_guard_ngram_size: int = 4             # n in n-gram comparison
    output_guard_enabled: bool = True

    # ── Groq API (key read automatically by SDK) ───────────────────────────
    groq_api_key: str = ""  # populated from GROQ_API_KEY env var by SDK
    gemini_api_key: str = ""  # populated from GEMINI_API_KEY env var by SDK

    # ── Detector timeout (seconds) ─────────────────────────────────────────
    detector_timeout: float = 15.0
    # Pending chunks remain excluded from answer context. This controls whether
    # chat explains that a matching document is awaiting review.
    pending_document_notice_enabled: bool = True
    groq_retry_attempts: int = 3
    groq_retry_wait_min: float = 1.0
    groq_retry_wait_max: float = 10.0
    # ── Demo mode ──────────────────────────────────────────────────────────
    demo_mode: bool = False
    # ── Audit scheduler ────────────────────────────────────────────────────
    audit_scheduler_enabled: bool = True
    max_access_grant_hours: int = 24

settings = Settings()
