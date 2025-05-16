# MilesLib

MilesLib is a modular utility framework for Python projects that need structured logging, CLI tooling, file management, retry/timer decorators, and automatic boilerplate generation. It is designed for scalable internal tooling, test scaffolding, and rapid developer onboarding.

---

## Features

* **Structlog-powered logger** with rotating file + console handlers
* **Configurable retry** with exponential backoff (`sm.attempt()`)
* **Timing decorator** (`@sm.timer`) with structured logging
* **CLI engine** via `click` with subcommands
* **Jinja2-based test boilerplate renderer**
* **File & path utilities** (`validate_file`, `ensure_file_with_default`, etc.)
* **Pytest scaffolding** with fixtures, test generation, and CLI tests

---

## Installation (WIP)

```bash
pip install -e .
```

---

## Project Structure

```

```

---

## Example Usage

### CLI: Initialize a project

```bash
python mileslib.py init myproject
```

### CLI: Render a test stub

```bash
python mileslib.py render MyClass
```

### Programmatic Usage

```python
from mileslib import MilesLib
ml = MilesLib()
ml.logger.info("Logger is working")
```

---

## Example Log Output

```json
{
  "event": "Starting GET request",
  "url": "http://example.com",
  "timestamp": "2025-05-16T16:52:13.512052Z"
}
{
  "event": "Timer completed",
  "label": "http_get",
  "duration": "0.005s"
}
```

---

# 📖 Sprint Plan: MilesLib + PhazeDeck

---

## Sprint 1 (Week 1): MilesLib Core Library

### Objectives

* Build core modules: `log`, `config`, `exists`, `request`, `timer`
* Initialize Git repo, project structure, and internal test coverage
* Establish logging + config file standards

### Deliverables

* `mileslib` Python package with reusable utilities
* Unit tests and pytest scaffold
* Early CLI stub

---

## Sprint 2 (Week 2): Project Scaffolding CLI

### Objectives

* Build `mileslib init` command with:

  * Django scaffold (admin-ready, AAD auth)
  * FastAPI scaffold (async routes, Docker-ready)
  * PostgreSQL + shared config support
* Inject `.env`, `Dockerfile`, basic `README`

### Deliverables

* `mileslib init <name> --stack azure-hybrid`
* Template-based project generator
* One-click local bootable backend stack

---

## Sprint 3 (Week 3): Azure Deployment Pipeline

### Objectives

* Azure App Services for Django + FastAPI
* PostgreSQL config and connection via `.env`
* Add TLS via Let's Encrypt
* Azure Front Door: path-based routing for `/admin` and `/api`

### Deliverables

* Live staging site deployed from generated project
* Internal deployment doc
* CI/CD script draft (GitHub Actions or manual deploy)

---

# Phase 2: Core Feature Implementation (Weeks 4–7)

## Sprint 4 (Week 4): ZoomInfo API Integration

### Objectives

* Create `mileslib.zoominfo` client:

  * `enrich_lead`, `search_contacts`, `company_lookup`
* FastAPI endpoints:

  * `POST /api/enrich_lead`
  * `POST /api/search_leads`
* Secure ZoomInfo API key in `.env` or Azure Key Vault
* Extend `Lead` model with enrichment fields

### Frontend

* Add "Enrich Lead" button in Django admin
* Display company/org info in modal

### Deliverables

* Fully working ZoomInfo integration
* FastAPI + Django hook-ins
* Sample enrichment and test records

---

## Sprint 5 (Week 5): Models, Auth, UI Scaffolding

### Objectives

* Django models: `Lead`, `Activity`, `SalesResource`, `UserProfile`
* Azure AD login with `django-auth-adfs`
* Base layout template (logo, navbar, profile menu)
* Role-based permissions + groups

### Deliverables

* Admin access with assigned permissions
* Authenticated UI structure across roles

---

## Sprint 6 (Week 6): Live Feed, Filtering, Metrics Panel

### Objectives

* FastAPI endpoints:

  * `/api/feed`
  * `/api/metrics`
* Filtering logic: by user, activity type, date
* Sidebar data logic (top reps, total activities)

### Frontend

* Polling-based activity feed
* Filter bar (HTMX or AJAX)
* Right panel metrics (Chart.js or basic templates)

### Deliverables

* Dynamic dashboard homepage
* Real-time updates + searchable feed

---

## Sprint 7 (Week 7): Sales Dashboards + Activity Logging

### Objectives

* User dashboard:

  * Daily agenda, assigned leads
  * Weekly activity summary
* FastAPI endpoints:

  * `POST /api/log_activity`
* Optional template fills (e.g., "Left voicemail")

### Frontend

* Logging forms
* Summary charts
* Assigned leads quick actions

### Deliverables

* Personal dashboards for reps
* Lead interaction and timestamped notes

---

## Sprint 8 (Week 8): Admin Tools + Resource Center

### Objectives

* Admin dashboard:

  * Upload/edit/delete resources
  * CSV lead import + manual/auto assignment
  * KPIs + leaderboard view
* FastAPI endpoints:

  * `/api/report`
  * `/api/leaderboard`
* Export to CSV + PDF (via WeasyPrint)

### Frontend

* Admin-only controls
* Resource library filters
* “Used” tracking logic

### Deliverables

* Fully functioning admin UI
* Report export functionality
* Resource usage analytics

---

# Phase 3: QA, Security & Production Launch (Weeks 8–9)

## Sprint 9 (Week 9): Internal QA + Hardening

### Objectives

* Run:

  * Manual QA (lead logging, search, dashboard, metrics)
  * Security checklist (token auth, rate limits, endpoint control)
  * Azure firewall rules (restrict access to Front Door only)
* Fix:

  * UI/UX bugs
  * API validation gaps
  * DB issues from enrichment or imports

### Deliverables

* Stable, hardened MVP
* Production lock-down complete
* Feedback loop from internal testers

---

## Sprint 10 (Week 10): Beta Feedback, Final Polish

### Objectives

* Onboard users (sales, admin, manager roles)
* Gather and apply internal feedback
* Final documentation:

  * Admin guide
  * Internal SOPs
  * Endpoint summary

### Deliverables

* Production deployment at `app.phazebreak.com`
* Fully documented internal system
* Sign-off-ready build

# Sprint 2 (Week 2): Project Scaffolding CLI

## Weekly Objective

Build a CLI-driven scaffolding engine using `mileslib init` that generates a backend project based on FastAPI or Django with PostgreSQL, .env injection, and Azure-ready deployment files.

---

## Day-by-Day Breakdown

### Day 1 (Monday): Scaffold Planning + CLI Interface

**Goal:** Define CLI UX and stub out subcommands.

**Tasks:**

* Finalize `mileslib init` syntax and CLI help text
* Add `--stack` flag with options: `django`, `fastapi`, `azure-hybrid`
* Create `cli.main:init()` with logging and `click.pass_context`
* Stub `scaffold/project_init.py:run_init()` with print/log output
* Log CLI activity to shared logger

**Checkpoint:** `mileslib init testproject --stack fastapi` prints expected messages

---

### Day 2 (Tuesday): Template System + FastAPI Bootstrap

**Goal:** Lay foundation for a template system and render FastAPI.

**Tasks:**

* Create `templates/fastapi/` directory
* Write `render_folder(template_dir, dest_dir, context)` logic using Jinja2
* Add `.env`, `Dockerfile`, `README.md` placeholders
* Generate `main.py`, `app/`, and `requirements.txt` with async route
* Log completed scaffolds to CLI output and logger

**Checkpoint:** Local FastAPI app bootable from CLI-generated folder

---

### Day 3 (Wednesday): Django Stack Integration

**Goal:** Enable Django template generation with optional AAD support.

**Tasks:**

* Create `templates/django/` with base project
* Add `manage.py`, `settings.py`, and `wsgi.py`
* Inject optional AAD logic via `django-auth-adfs`
* Unify `.env` layout with FastAPI
* Validate project is bootable with SQLite or local PostgreSQL

**Checkpoint:** Both Django and FastAPI can be generated from CLI with `--stack`

---

### Day 4 (Thursday): PostgreSQL Config + Shared Env

**Goal:** Enable stack-neutral .env and PostgreSQL configuration.

**Tasks:**

* Add `DATABASE_URL` and `SECRET_KEY` to `.env`
* Inject `python-dotenv` or `os.environ` loading logic
* Add Dockerfile for PostgreSQL in both stacks
* Add `mileslib.scaffold.env_util` to parse, validate, and inject envs
* Confirm apps run with `.env` settings via `uvicorn` or `runserver`

**Checkpoint:** CLI-generated apps connect to PostgreSQL using `.env`

---

### Day 5 (Friday): Docs, Tests, Final Polish

**Goal:** Polish CLI UX and wrap test + doc coverage.

**Tasks:**

* Add CLI usage examples to README
* Write tests for CLI commands with `CliRunner`
* Validate idempotency (re-run into existing dir = handled gracefully)
* Confirm `--stack` logic triggers correct template
* Finish test coverage and push results to HTML

**Checkpoint:** CLI, templates, and .env logic fully covered and documented

---

## Deliverables by End of Week

* `mileslib init <name> --stack <stack>` CLI tool
* Template engine supporting Django and FastAPI
* PostgreSQL and .env config for local/remote
* Project logs on CLI usage
* Dev-ready backend generated with one command
