# Retrieval Rebuild Report

| Item | Status | Evidence |
|---|---|---|
| 1. Offline models | PASS | Both local model directories populated from cache; MiniLM and DeBERTa load locally; Chroma uses explicit vectors and cosine distance. |
| 2. Token chunking/reindex | PASS | MiniLM max_seq_length=256; 14 chunks measured at 13–202 tokens (median 167.5); 9 active, 4 pending_judge, 1 quarantined. |
| 3. Relevance cutoff | PASS | Dev chose min_similarity=0.45 and relative_cutoff=0.82; test once: recall 0.60, irrelevant share 0.455, negative-empty 1.00; old top-5: 1.00, 0.90, 0.00. |
| 4. Tests/E2E | BLOCKED | Focused tests: 10 passed; full suite: 73 passed, 8 failed in 22.05s; offline E2E: 5 passed, 4 failed. |

The full-suite failures are in grant/RBAC, the retired permission route, and the lab runner; those areas were not changed, and no tests were weakened. Offline E2E failed the two checks expecting pending documents to be immediately retrievable, the quarantined-chunk trace assertion, and the hosted Gemini-disagreement check. Provider-backed E2E remains unverified because it sends document text to hosted services.

Changed: `app/config.py`, `app/embeddings.py`, `app/vector_store.py`, `app/ingest.py`, `app/retrieval.py`, `app/pipeline.py`, `app/detectors/deberta.py`, `app/main.py`, `scripts/download_models.py`, `scripts/reindex.py`, `scripts/e2e_test.py`, `eval/retrieval_eval.py`, `eval/retrieval_eval.json`, `reports/retrieval_baseline.json`, `reports/retrieval_eval_results.json`, `.env.example`, `README.md`, `AGENTS.md`, retrieval tests.

Remaining: resolve the 8 existing suite failures; approve/retry the 4 pending chunks through the admin/security review flow; run provider-backed E2E only in an environment authorized to send sample document text to those providers.

# Persistent Conversations - Implementation Status

| Item | Status | Evidence |
|---|---|---|
| Authenticated conversation API, owner-only access, rename, soft delete | PASS | Conversation API tests cover CRUD, cross-user 404s (including admin/security/auditor), deletion, and audit-log retention. |
| Message persistence, title generation, context window, blocked prompt privacy | PASS | Tests verify message order, first-message titles, last 10 plain turns, model request shape, and blocked-text redaction. |
| Partial stream persistence, trace filtering, retention purge, expired grants | PASS | Interrupted stream, owner trace redaction, retention purge, and mocked-clock access expiry tests pass. |
| Persistent frontend chat, sidebar, reload, remount, rename/delete, model choice | PASS | 6 Vitest tests pass; frontend production build succeeds. |
| Required focused backend and access-matrix checks | PASS | 13 passed with `--timeout=60`, including the role document matrix and expired-grant follow-up. |
| Broader legacy access-model checks | BLOCKED | An earlier full-file run had 3 unrelated grant-authorization failures; those paths were not changed. |

# Phase 4 - Access Model Rebuild Status

| Item | Status | Evidence |
|---|---|---|
| 1. Data-driven roles and scoped capabilities | BLOCKED | Six roles, legacy mapping, capability catalog, rank and feature metadata are wired through `/me`; backend suite did not complete. |
| 2. Delegation authorization and audit | BLOCKED | `authorize_delegation` guards grants, role changes, capability changes and document release; direct-route test run stalled without a result. |
| 3. Central `can_read` policy | BLOCKED | `can_read` is wired to document lists, retrieval, output guard and auditor redaction; access matrix run did not complete. |
| 4. Temporary grants and UI | BLOCKED | Grant/revoke/list/request/approval screens and endpoints are connected; frontend production build passed, backend behavior remains unverified. |
| 5. Seed users and documents | PASS | Startup migration reported all 12 role×department combinations; sample documents include public, internal, department and confidential levels. |
| 6. Required tests and E2E | BLOCKED | Backend suite emitted `FFF.F.........` then stalled; `test_access_routes.py` also stalled. E2E ran once and failed with Windows `WinError 10013` socket denial. |

## Remaining for Phase 4
- Resolve why the backend suite and direct-route test hang, then obtain a completed backend test summary and successful E2E output.
- Review the access-matrix and expiry/revocation assertions after the suite can complete.
- Verify the role-based access screens in a browser; the frontend production build succeeds.
- Review UI flows and ensure no development credentials or default JWT secret are used for shared demos.

# Phase 3 Part A - Implementation & Status

## Status Table

| Item | Requirement | Status | Evidence |
|---|---|---|---|
| 1a | Audit endpoints allow admin, security, security_reviewer; settings admin-only | PASS | `tests/test_audit.py::test_security_reviewer_access_and_settings_restriction` PASSED |
| 1a | Seed security_reviewer user | PASS | `security_user` created with `security_reviewer` role in `app/auth.py` |
| 1b | Remove demo credentials and quick-fill buttons from frontend | PASS | `frontend/src/LoginPage.jsx` sanitized; `DEMO_MODE` flag added to `app/config.py` |
| 1b | Seed users from env vars or gitignored file | PASS | `seed_users.json` added & gitignored in `.gitignore`; loaded dynamically in `app/auth.py` |
| 1c | Add `source_type` ('live'/'lab') column to log rows; stats/audit filter live by default | PASS | Migrations in `app/db.py`; `tests/test_audit.py` passes with source filtering in stats & collector |
| 1d | Investigate 3 flagged chunks with 0 quarantined docs | PASS | Chunk 1 (Policy, DeBERTa=0.78, PG=0.01, Gemini 429 failed closed); Chunk 2 (Salary, DeBERTa=0.94, PG=0.005, Gemini benign); Chunk 3 (Poisoned, DeBERTa=1.0, PG=1.0). Fixed `parent_doc.is_quarantined = True` in `pipeline.py` & `ingest.py`. |
| 2a | Redaction before data reaches auditor model | PASS | `tests/test_audit.py::test_redaction_strips_canary_secrets_emails` PASSED |
| 2b | Strict JSON findings, defensive parsing, 1 retry | PASS | `tests/test_audit.py::test_parse_auditor_json_normalizes_schema` PASSED |
| 2c | Lab validation with candidate attacks (never used for tuning) | PASS | `tests/test_audit.py::test_validate_findings_links_to_lab_results` PASSED (split='candidate') |
| 2d | Interval and event-count scheduling with mocked clock | PASS | `tests/test_audit.py::test_scheduler_interval_mode_mock_clock` & `test_scheduler_event_count_mode` PASSED |
| 2e | Human approval before export; pseudonymized JSON/HTML export | PASS | `POST /audit/runs/{id}/approve` and `GET /audit/runs/{id}/export` enforced in `app/main.py` |
| 3 | Employee gets 403 on every admin/security route | PASS | `tests/test_audit.py::test_employee_403_on_admin_and_security_routes` PASSED (16 routes verified) |
| Total | Full test suite passing | PASS | 48 passed, 0 failed in 28.96s (`pytest -v`) |

## Phase 3 Part B - UI Status

| Item | Requirement | Status | Evidence |
|---|---|---|---|
| 4a | Roles & document permissions matrix | IMPLEMENTED | `frontend/src/RolesPage.jsx`, admin-only editing with read-only security view |
| 4b | Document upload and quarantined chunk review/release | IMPLEMENTED | `frontend/src/DocumentsPage.jsx`; release now restores full chunk text to Chroma |
| 4c | Security log visualization | IMPLEMENTED | `frontend/src/AdminPage.jsx` seven-day live scan/chat activity chart |
| 4d | Browser UI verification and live traffic demonstration | NOT YET VERIFIED | Run locally with configured API keys and verify each role flow |

## Remaining
- Verify the UI manually in a browser and capture a live traffic demonstration.
- Replace development seed credentials and default JWT secret before any shared or deployed demo.
