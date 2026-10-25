"""Download request-time models into the repository's local models directory."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from huggingface_hub import snapshot_download
from huggingface_hub.constants import HF_HUB_CACHE
from huggingface_hub.errors import LocalEntryNotFoundError

from app.config import settings


def download_models(local_files_only: bool = False) -> None:
    models = (
        (settings.embedding_model, Path(settings.embedding_model_path)),
        (settings.deberta_model, Path(settings.deberta_model_path)),
    )
    for model_id, destination in models:
        destination.mkdir(parents=True, exist_ok=True)
        print(f"Preparing {model_id} in {destination}")
        try:
            snapshot = snapshot_download(
                repo_id=model_id,
                local_files_only=local_files_only,
            )
        except LocalEntryNotFoundError:
            if not local_files_only:
                raise
            cache_repo = Path(HF_HUB_CACHE) / f"models--{model_id.replace('/', '--')}"
            cached_revision = (cache_repo / "refs" / "main").read_text(encoding="utf-8").strip()
            snapshot = snapshot_download(
                repo_id=model_id,
                revision=cached_revision,
                local_files_only=True,
            )
        shutil.copytree(snapshot, destination, dirs_exist_ok=True)
        print(f"Ready: {destination}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--local-files-only",
        action="store_true",
        help="Populate ./models from the Hugging Face cache without contacting the network.",
    )
    download_models(local_files_only=parser.parse_args().local_files_only)
