from __future__ import annotations

import datetime as dt
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.access_config import ROLE_POLICY
from app.auth import create_access_token
from app.db import (
    Base,
    ChatLog,
    Conversation,
    Department,
    Message,
    Role,
    User,
    get_db,
    purge_expired_conversations,
)
from app.llm import generate_answer
from app.pipeline import DefenseConfig, PipelineResult, SecurityTrace, run_chat_pipeline
from app.retrieval import RetrievedChunk


@pytest.fixture
def conversation_api(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    db = factory()
    hr = Department(name="HR")
    engineering = Department(name="Engineering")
    db.add_all([hr, engineering])
    db.flush()
    roles = {
        name: Role(name=name, capabilities_json=json.dumps(policy))
        for name, policy in ROLE_POLICY.items()
    }
    db.add_all(roles.values())
    db.flush()
    users = {}
    for role_name in ("employee", "super_admin", "security_admin", "auditor"):
        user = User(
            username=f"chat_{role_name}",
            hashed_password="unused",
            role_id=roles[role_name].id,
            department_id=engineering.id,
        )
        db.add(user)
        users[role_name] = user
    db.commit()

    def override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    main.app.dependency_overrides[get_db] = override_db
    client = TestClient(main.app, raise_server_exceptions=False)
    tokens = {
        role: {"Authorization": f"Bearer {create_access_token({'sub': user.username})}"}
        for role, user in users.items()
    }
    monkeypatch.setattr(main.settings, "chat_context_turns", 10)
    yield client, db, factory, users, tokens
    main.app.dependency_overrides.pop(get_db, None)
    db.close()
    engine.dispose()


def _ok_result(answer="answer"):
    return PipelineResult(answer=answer, security_trace=SecurityTrace())


def test_chat_persists_messages_and_passes_only_last_ten_plain_turns(conversation_api):
    client, db, factory, users, tokens = conversation_api
    response = client.post(
        "/conversations", headers=tokens["employee"], json={"title": "History"}
    )
    conversation_id = response.json()["id"]
    conversation = db.get(Conversation, conversation_id)
    for index in range(12):
        db.add_all([
            Message(conversation=conversation, role="user", content=f"user-{index}"),
            Message(conversation=conversation, role="assistant", content=f"assistant-{index}"),
        ])
    db.commit()

    def generate(**kwargs):
        assert kwargs["conversation_history"] == [
            {"role": role, "content": f"{role}-{index}"}
            for index in range(2, 12)
            for role in ("user", "assistant")
        ]
        assert "security_trace" not in kwargs["conversation_history"][0]
        assert all("retrieved chunk" not in item["content"] for item in kwargs["conversation_history"])
        with factory() as read_session:
            newest = (
                read_session.query(Message)
                .filter_by(conversation_id=conversation_id)
                .order_by(Message.id.desc())
                .first()
            )
            assert newest.role == "user"
            assert newest.content == "follow-up"
        return _ok_result("follow-up answer")

    with patch("app.main.run_chat_pipeline", side_effect=generate):
        chat = client.post(
            "/chat",
            headers=tokens["employee"],
            json={"question": "follow-up", "model": "large", "conversation_id": conversation_id},
        )
    assert chat.status_code == 200
    saved = client.get(f"/conversations/{conversation_id}", headers=tokens["employee"])
    messages = saved.json()["messages"]
    assert [message["content"] for message in messages[-2:]] == ["follow-up", "follow-up answer"]
    assert [message["role"] for message in messages[-2:]] == ["user", "assistant"]


def test_llm_receives_plain_history_separate_from_fresh_retrieved_context():
    history = [
        {"role": "user", "content": "Earlier question"},
        {"role": "assistant", "content": "Earlier answer"},
    ]
    expected_messages = [
        {"role": "system", "content": "Fresh retrieved context"},
        *history,
        {"role": "user", "content": "Current question"},
    ]
    captured = {}
    completion = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="answer"))]
    )
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(
                create=lambda **kwargs: captured.update(kwargs) or completion
            )
        )
    )
    with patch("app.llm._get_client", return_value=client), patch(
        "app.llm._resolve_model", return_value=("test-model", {})
    ):
        answer = generate_answer(
            "Fresh retrieved context",
            "Current question",
            conversation_history=history,
        )
    assert answer == "answer"
    assert captured["messages"] == expected_messages
    assert all(set(message) == {"role", "content"} for message in history)


def test_chat_creates_conversation_with_first_sixty_characters(conversation_api):
    client, _, _, _, tokens = conversation_api
    question = "x" * 75
    with patch("app.main.run_chat_pipeline", return_value=_ok_result()):
        response = client.post(
            "/chat",
            headers=tokens["employee"],
            json={"question": question, "model": "large"},
        )
    assert response.status_code == 200
    conversation_id = response.json()["conversation_id"]
    loaded = client.get(f"/conversations/{conversation_id}", headers=tokens["employee"])
    assert loaded.json()["title"] == question[:60]

    blank = client.post(
        "/conversations", headers=tokens["employee"], json={"title": "New chat"}
    ).json()
    with patch("app.main.run_chat_pipeline", return_value=_ok_result()):
        client.post(
            "/chat",
            headers=tokens["employee"],
            json={
                "question": question,
                "model": "large",
                "conversation_id": blank["id"],
            },
        )
    loaded_blank = client.get(
        f"/conversations/{blank['id']}", headers=tokens["employee"]
    )
    assert loaded_blank.json()["title"] == question[:60]


@pytest.mark.parametrize("other_role", ["super_admin", "security_admin", "auditor"])
def test_conversation_is_private_even_from_privileged_roles(conversation_api, other_role):
    client, _, _, _, tokens = conversation_api
    created = client.post(
        "/conversations", headers=tokens["employee"], json={"title": "Private"}
    )
    conversation_id = created.json()["id"]
    response = client.get(f"/conversations/{conversation_id}", headers=tokens[other_role])
    assert response.status_code == 404


def test_soft_delete_hides_conversation_and_retains_audit_logs(conversation_api):
    client, db, _, users, tokens = conversation_api
    created = client.post(
        "/conversations", headers=tokens["employee"], json={"title": "Delete me"}
    )
    conversation_id = created.json()["id"]
    db.add(
        ChatLog(
            user_id=users["employee"].id,
            question_preview="audit record",
            model_used="large",
            source_type="live",
        )
    )
    db.commit()

    deleted = client.delete(
        f"/conversations/{conversation_id}", headers=tokens["employee"]
    )
    assert deleted.status_code == 200
    assert client.get(
        f"/conversations/{conversation_id}", headers=tokens["employee"]
    ).status_code == 404
    listed = client.get("/conversations", headers=tokens["employee"]).json()["items"]
    assert all(item["id"] != conversation_id for item in listed)
    assert db.query(ChatLog).filter_by(user_id=users["employee"].id).count() == 1


def test_stored_trace_is_filtered_for_owner_role(conversation_api):
    client, db, _, users, tokens = conversation_api
    conversation = Conversation(user_id=users["employee"].id, title="Trace")
    db.add(conversation)
    db.flush()
    db.add(
        Message(
            conversation_id=conversation.id,
            role="assistant",
            content="safe answer",
            security_trace=json.dumps(
                {"output_guard": {"triggered": True, "matched": "SECRET", "matched_value": "SECRET"}}
            ),
        )
    )
    db.commit()
    response = client.get(
        f"/conversations/{conversation.id}", headers=tokens["employee"]
    )
    trace = response.json()["messages"][0]["security_trace"]["output_guard"]
    assert trace == {"triggered": True}


def test_blocked_prompt_is_redacted_from_conversation_views(conversation_api):
    client, _, _, _, tokens = conversation_api
    trace = SecurityTrace(prompt_blocked=True, block_reason="injection")
    with patch("app.main.run_chat_pipeline", return_value=PipelineResult(None, trace)):
        response = client.post(
            "/chat",
            headers=tokens["employee"],
            json={"question": "do not reveal this blocked text", "model": "large"},
        )
    conversation_id = response.json()["conversation_id"]
    loaded = client.get(f"/conversations/{conversation_id}", headers=tokens["employee"])
    contents = [message["content"] for message in loaded.json()["messages"]]
    assert "[Blocked prompt]" in contents
    assert "do not reveal this blocked text" not in str(loaded.json())


def test_interrupted_stream_persists_partial_assistant_message(conversation_api):
    client, _, factory, _, tokens = conversation_api
    def interrupted_stream():
        yield "generated "
        yield "so far"
        raise RuntimeError("stream interrupted")

    with patch(
        "app.main.run_chat_pipeline",
        return_value=PipelineResult(None, SecurityTrace(), stream=interrupted_stream()),
    ):
        response = client.post(
            "/chat",
            headers=tokens["employee"],
            json={"question": "streaming question", "model": "large", "stream": True},
        )
    conversation_id = int(response.headers["X-Conversation-ID"])
    assert response.status_code == 200
    with factory() as read_session:
        assistant = (
            read_session.query(Message)
            .filter_by(conversation_id=conversation_id, role="assistant")
            .one()
        )
        assert assistant.content == "generated so far"
        assert assistant.status == "partial"


def test_completed_stream_persists_complete_assistant_message(conversation_api):
    client, _, factory, _, tokens = conversation_api

    def complete_stream():
        yield "complete "
        yield "answer"

    with patch(
        "app.main.run_chat_pipeline",
        return_value=PipelineResult(None, SecurityTrace(), stream=complete_stream()),
    ):
        response = client.post(
            "/chat",
            headers=tokens["employee"],
            json={"question": "streaming question", "model": "large", "stream": True},
        )
    conversation_id = int(response.headers["X-Conversation-ID"])
    with factory() as read_session:
        assistant = (
            read_session.query(Message)
            .filter_by(conversation_id=conversation_id, role="assistant")
            .one()
        )
        assert assistant.content == "complete answer"
        assert assistant.status == "complete"


def test_pipeline_stream_survives_request_session_closing(conversation_api):
    _, db, factory, users, _ = conversation_api

    def token_stream():
        yield "generated "
        yield "answer"

    with patch(
        "app.pipeline.retrieve_chunks",
        return_value=[
            RetrievedChunk(
                chroma_id="chunk-1",
                text="fresh document context",
                doc_id=1,
                chunk_index=0,
                distance=0.1,
            )
        ],
    ), patch("app.pipeline.generate_answer", return_value=token_stream()):
        result = run_chat_pipeline(
            "question",
            "large",
            users["employee"],
            db,
            stream=True,
            defense_config=DefenseConfig(
                scan_prompt=False,
                rbac_filter=False,
                scan_chunks=False,
                output_guard=False,
            ),
        )

    db.close()
    assert "".join(result.stream) == "generated answer"
    with factory() as read_session:
        log = read_session.query(ChatLog).filter_by(user_id=users["employee"].id).one()
        assert log.answer_preview == "generated answer"


def test_chat_saves_partial_answer_when_model_stream_fails(conversation_api):
    client, _, factory, _, tokens = conversation_api

    def interrupted_tokens():
        yield "partial answer"
        raise RuntimeError("model stream interrupted")

    no_defenses = DefenseConfig(
        scan_prompt=False,
        rbac_filter=False,
        scan_chunks=False,
        output_guard=False,
    )
    with patch(
        "app.pipeline.retrieve_chunks",
        return_value=[
            RetrievedChunk(
                chroma_id="chunk-1",
                text="fresh document context",
                doc_id=1,
                chunk_index=0,
                distance=0.1,
            )
        ],
    ), patch("app.pipeline.generate_answer", return_value=interrupted_tokens()), patch(
        "app.main.run_chat_pipeline",
        side_effect=lambda **kwargs: run_chat_pipeline(
            **kwargs, defense_config=no_defenses
        ),
    ):
        response = client.post(
            "/chat",
            headers=tokens["employee"],
            json={"question": "streaming question", "model": "large", "stream": True},
        )

    conversation_id = int(response.headers["X-Conversation-ID"])
    with factory() as read_session:
        assistant = (
            read_session.query(Message)
            .filter_by(conversation_id=conversation_id, role="assistant")
            .one()
        )
        assert assistant.content == "partial answer"
        assert assistant.status == "partial"


def test_retention_purges_conversations_and_messages_only(conversation_api, monkeypatch):
    _, db, _, users, _ = conversation_api
    conversation = Conversation(
        user_id=users["employee"].id,
        title="Expired",
        created_at=dt.datetime(2020, 1, 1),
        updated_at=dt.datetime(2020, 1, 1),
    )
    db.add(conversation)
    db.flush()
    db.add(Message(conversation_id=conversation.id, role="user", content="old message"))
    audit_log = ChatLog(
        user_id=users["employee"].id,
        question_preview="unaffected audit",
        model_used="large",
        source_type="live",
    )
    db.add(audit_log)
    db.commit()
    conversation_id = conversation.id
    monkeypatch.setattr("app.db.settings.conversation_retention_days", 365)

    assert purge_expired_conversations(db, now=dt.datetime(2022, 1, 1)) == 1
    assert db.get(Conversation, conversation_id) is None
    assert db.query(Message).filter_by(conversation_id=conversation_id).count() == 0
    assert db.query(ChatLog).filter_by(id=audit_log.id).count() == 1
