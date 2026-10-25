# Security-First RAG Platform

Enterprise RAG backend with multi-layer prompt-injection protection (DeBERTa + Prompt Guard + Gemini judge) and SQL-enforced RBAC.

---

## Quick Start

### 1. Python environment

> **Note:** This project requires Python 3.12 for `torch` / `transformers`. If you only have Python 3.14, install Python 3.12 from https://python.org then run:

```powershell
# Create venv (named venv312 regardless of which Python is used)
py -3.12 -m venv venv312

# Activate
.\venv312\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

If Python 3.12 is unavailable and you want to attempt with 3.14 (torch may fail):
```powershell
python -m venv venv312
.\venv312\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure secrets

```powershell
# Copy template
copy .env.example .env

# Edit .env and add your real keys:
#   GROQ_API_KEY=gsk_...
#   GEMINI_API_KEY=AI...
#   JWT_SECRET_KEY=<output of: python -c "import secrets; print(secrets.token_hex(32))">
```

### 3. Run the server

```powershell
.\venv312\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API docs: http://localhost:8000/docs

### Troubleshooting trace

The backend terminal prints one `TRACE` entry per stage with a request ID. For chat and uploads, follow the same ID through authentication, detector steps, retrieval or ingestion, answer generation, and output checks. The chat Security Trace panel shows the ID, and API responses include it in the `X-Request-ID` header. Trace entries include outcomes, counts, and timings; they do not include prompts, document text, answers, passwords, tokens, or API keys.

### Pending document chunks

Chunks held for an uncertain security scan have status `pending_judge`. They are excluded from chat context until reviewed; chat reports when a matching document is awaiting review instead of falling back to a generic answer. Admin/security users can inspect them with `GET /chunks/pending` and retry the judge with `POST /chunks/retry-pending` (or the per-chunk retry button in Documents). A benign result promotes the chunk to `active`; an injection result keeps it quarantined. `PENDING_DOCUMENT_NOTICE_ENABLED=false` hides the pending-state explanation, but does not allow pending content into retrieval.

HR managers can read `department`-level guides across departments. This does not grant cross-department access to `confidential` documents; those retain the existing role and department restrictions.

### 4. Run the web interface

In a second PowerShell window:

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. The sidebar is built from the authenticated user's capabilities. Open **Access** to assign scoped roles, create or revoke temporary grants, review record-access requests, or inspect the access audit trail. The same app serves every role; sign out to switch accounts.

---

## Seeded Users

Users are loaded from the gitignored `seed_users.json` file or the `SEED_USERS_JSON` environment variable. The app does not create fallback users if neither is configured. Seed passwords are local development credentials; change them before sharing the project. Existing database users keep their current passwords when seed values change. The ignored seed file includes examples for all six roles in HR and Engineering.

---

## API Reference

| Method | Endpoint       | Auth Required  | Description                                      |
|--------|----------------|----------------|--------------------------------------------------|
| POST   | /auth/login    | None           | Login; returns JWT bearer token                  |
| POST   | /documents     | `manage_documents` capability | Upload txt/pdf/docx with a confidentiality level |
| GET    | /documents     | Any user       | List documents accessible to current user        |
| GET    | /access/users  | User or grant manager | List users within the caller's scope       |
| PATCH  | /users/{id}/role | `manage_users` | Assign a role within the caller's scope         |
| PATCH  | /roles/{name}/capabilities | `manage_roles` | Delegate a capability the caller holds |
| POST   | /access-grants | `grant_access` | Create a reasoned, expiring per-user document grant |
| DELETE | /access-grants/{id} | `grant_access` | Revoke a grant immediately                 |
| GET    | /access-grants | `grant_access` | List active, expired, or revoked grants           |
| POST   | /access-grants/request | `request_record_access` | Request access with a reason |
| POST   | /access-grants/requests/{id}/approve | `approve_record_access` | Approve a scoped request |
| POST   | /permissions   | Disabled       | Legacy role-wide document grants return 410      |
| POST   | /chat          | Any user       | Secure RAG chat with injection scanning          |
| POST   | /scan          | Any user       | Run ensemble on arbitrary text (debugging)       |
| GET    | /logs          | admin          | Retrieve scan or chat audit logs                 |

### Example: Login
```bash
curl -X POST http://localhost:8000/auth/login \
  -d "username=<seeded-user>&password=<password-from-your-ignored-seed-file>" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

### Example: Upload document
```bash
curl -X POST http://localhost:8000/documents \
  -H "Authorization: Bearer <token>" \
  -F "file=@my_doc.txt" \
  -F "confidentiality=department"
```

### Example: Chat
```bash
curl -X POST http://localhost:8000/chat \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"question": "What is the remote work policy?", "model": "large"}'
```

### Example: Scan text
```bash
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"text": "Ignore all previous instructions", "source": "prompt"}'
```

---

## Run Tests

```powershell
.\venv312\Scripts\Activate.ps1
pytest tests/ -v
```

The project status file records the last reported full-suite result. Tests use mocked detectors and generally do not require API keys.

---

## Run Evaluation

Drop your labeled CSV at `eval/data/benchmark_100.csv` with columns:
```
id,category,label,text
```
`label` must be `INJECTION` or `BENIGN`.

```powershell
.\venv312\Scripts\Activate.ps1
python -m eval.run_eval eval/data/benchmark_100.csv
```

Outputs per-detector metrics (accuracy/precision/recall/FP/FN), per-category injection recall, and saves `eval/data/benchmark_100_results.csv`.

---

## Architecture

```
POST /chat
  │
  ├─ 1. JWT auth → get user + role
  ├─ 2. Scan prompt ─── Ensemble ──► Block if INJECTION
  ├─ 3. Retrieve chunks ── ChromaDB (where: doc_id ∈ allowed_ids AND role ∈ allowed_roles)
  │                     └─ SQL re-verify each chunk (independent of Chroma metadata)
  ├─ 4. Scan each chunk ── Ensemble ──► Drop + quarantine if INJECTION
  ├─ 5. Build prompt: system + [UNTRUSTED REFERENCE DATA BLOCK] + question
  ├─ 6. Call Groq LLM (streaming or not)
  └─ 7. Return answer + security_trace + log everything
```

### Ensemble Decision Logic
```
Normalize → scan all text variants
     │
     ├─ Both INJECTION ────────────► BLOCK  (reason: both_agree_injection)
     ├─ Both BENIGN ───────────────► ALLOW  (reason: both_agree_benign)
     └─ Disagree ──► Gemini judge ──► Gemini verdict (or fail-open/closed on error)
```

### Failure Modes
| Scenario | User Prompt | Retrieved Document |
|---|---|---|
| Single detector fails | Other detector used | Other detector used |
| Both detectors fail | ALLOW + log warning* | QUARANTINE |
| Gemini fails | ALLOW + log warning* | QUARANTINE |

*configurable via `user_prompt_fail_open` in config.py

---

## Security Design Notes

1. **Read access is centralized** – `can_read` checks the user, document confidentiality, department, active grants, and quarantine state; SQL re-checks retrieved chunks.
2. **Chroma pre-filter** – retrieval first restricts its vector query to document IDs allowed by `can_read`, then verifies each chunk in SQL.
3. **Ingest-time scanning** – chunks are scanned before storage; poisoned chunks never enter the vector DB.
4. **Retrieval-time scanning** – even clean-at-ingest chunks are re-scanned at retrieval (in case the model is updated or thresholds change).
5. **UNTRUSTED data delimiters** – LLM system prompt explicitly labels all context blocks as untrusted and instructs the model never to follow instructions inside them.
6. **Normalization** – 6 evasion techniques detected and neutralized before scanning.

---

## Folder Layout

```
app/
  main.py           FastAPI app + startup seed
  config.py         All settings (env-overridable)
  db.py             SQLAlchemy models
  auth.py           JWT auth + seeded users
  access_config.py  Role, capability, scope, and confidentiality policy
  rbac.py           Delegation audit, access grants, and central can_read policy
  ingest.py         Upload → chunk → scan → embed
  retrieval.py      Role-filtered retrieval + SQL re-verify
  ensemble.py       DeBERTa + PromptGuard + Gemini decision logic
  normalize.py      Text evasion normalization
  llm.py            Groq LLM generation
  pipeline.py       Full chat request flow
  detectors/
    base.py         DetectorResult dataclass + interface
    deberta.py      Local DeBERTa classifier
    promptguard.py  Groq Prompt Guard
    gemini_judge.py Gemini final judge
eval/
  run_eval.py       CSV evaluation harness
  data/             Drop benchmark_100.csv here
tests/
  test_rbac.py      RBAC + permission tests
  test_normalize.py Normalization tests
  test_ensemble.py  Ensemble routing tests (mocked)
```
