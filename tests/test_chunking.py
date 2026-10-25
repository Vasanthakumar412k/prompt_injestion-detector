from types import SimpleNamespace
from unittest.mock import patch

from app.config import settings
from app.ingest import chunk_text


class FakeTokenizer:
    def encode(self, text, add_special_tokens=True):
        tokens = text.split()
        return ([0] + tokens + [0]) if add_special_tokens else tokens

    def decode(self, tokens, skip_special_tokens=True):
        return " ".join(str(token) for token in tokens if token != 0)

    def num_special_tokens_to_add(self, pair=False):
        return 2


def test_chunks_obey_model_limit_and_preserve_token_overlap(monkeypatch):
    model = SimpleNamespace(tokenizer=FakeTokenizer(), max_seq_length=8)
    monkeypatch.setattr(settings, "chunk_size_tokens", 5)
    monkeypatch.setattr(settings, "chunk_overlap_tokens", 2)
    with patch("app.embeddings.get_embedding_model", return_value=model):
        chunks = chunk_text("one two three four five six seven eight nine")

    assert len(chunks) == 3
    encoded = [model.tokenizer.encode(chunk, add_special_tokens=True) for chunk in chunks]
    assert all(len(tokens) <= model.max_seq_length for tokens in encoded)
    assert chunks[0].split()[-2:] == chunks[1].split()[:2]
    assert chunks[1].split()[-2:] == chunks[2].split()[:2]
