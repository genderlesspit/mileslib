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
python mileslib_core.py init myproject
```

### CLI: Render a test stub

```bash
python mileslib_core.py render MyClass
```

### Programmatic Usage

```python
from tests.mileslib_core import MilesLib

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

Here’s a clean, markdown-ready documentation section you can paste into your `README.md`:

---

## `generate-cli` — CLI Boilerplate Generator

This command creates a new Click CLI command + pytest test using Jinja2 templates.

### Output Files

It generates two files in `tests/.dev/cli/`:

* `cli_<command_name>.py` — the actual CLI command
* `test_cli_<command_name>.py` — the pytest test for it

---

### Usage

```bash
python -m mileslib generate-cli <command_name> [args...] --opt <opt1> --opt <opt2> ...
```

### Arguments

| Name           | Type    | Description                    |
| -------------- | ------- | ------------------------------ |
| `command_name` | `str`   | Name of the CLI command        |
| `args...`      | `str[]` | Positional arguments to accept |

---

### Options

```bash
--opt "name:type:default:help"
--docstring "Some description"
```

Each `--opt` flag must follow this format:

```
name:type:default:help
```

For example:

```bash
--opt force:bool:True:"Force deploy"
--opt retries:int:3:"Retry attempts"
```

---

### ✅ Example

```bash
python -m mileslib generate-cli deploy region env --opt force:bool:True:"Force deploy" --opt retries:int:3:"Retry attempts"
```

Generates:

* `tests/.dev/cli_deploy.py`:

  ```python
  @click.command()
  @click.option("--force", is_flag=True, default=True, help="Force deploy")
  @click.option("--retries", type=int, default=3, help="Retry attempts")
  @click.argument("region")
  @click.argument("env")
  def deploy(...): ...
  ```

* `tests/.dev/test_cli_deploy.py`:

  ```python
  def test_deploy_invokes():
      runner = CliRunner()
      result = runner.invoke(deploy, ["test_region", "test_env", "--force", "True", "--retries", "3"])
      assert result.exit_code == 0
  ```

---

### Template Location

| Template file | Path                              |
| ------------- | --------------------------------- |
| CLI Jinja2    | `config/_cli_command_template.j2` |
| Test Jinja2   | `config/_test_cli_template.j2`    |

---

# Sprint Plan: MilesLib + PhazeDeck

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

## Key Goal:

MilesLib `init` should generate a deploy-ready project skeleton with:

* Django (admin/auth)
* FastAPI (REST/async)
* PostgreSQL config
* Shared config/logging
* Azure deploy files (Docker, az webapp, secrets)
* Optional Redis + Celery setup

---

### Command

```bash
mileslib init project-name --stack azure-hybrid
```

### It Auto-Generates:

#### 1. Folder Structure

```
project-name/
├── django_app/
│   ├── manage.py
│   ├── settings.py
│   └── urls.py
├── fastapi_app/
│   ├── main.py
│   └── routes/
│       └── test.py
├── shared/
│   ├── mileslib/  (symlink or package import)
│   └── config.json
├── docker/
│   ├── django.Dockerfile
│   ├── fastapi.Dockerfile
│   └── compose.yml
├── deploy/
│   ├── azure_frontdoor.tf
│   └── appservice_config.json
└── README.md
```

#### 2. Included Modules

| Module     | Tool                                     | Notes                                    |
| ---------- | ---------------------------------------- | ---------------------------------------- |
| Django     | Admin panel + Azure AD login scaffold    | Uses `django-auth-adfs`                  |
| FastAPI    | Async job API + WebSocket                | Uses `fastapi`, `uvicorn`, `python-jose` |
| PostgreSQL | Common DB schema + env config            | Optional: init migration                 |
| Auth       | Shared Azure AD tokens across both apps  | Uses `msal`, `authlib`                   |
| MilesLib   | Logging, config, utilities               | Imported in both Django + FastAPI        |
| Deploy     | Docker + Terraform + Azure CLI templates | App Service + PostgreSQL + Front Door    |

---

## Sprint 2: 5-Day Breakdown

### Day 1 (Monday): CLI Interface & Command Logic

**Goal:** Define the `mileslib init` CLI UX and wire up `--stack` support.

* Define CLI signature: `mileslib init <name> --stack <stack>`
* Add stack flag: `fastapi`, `django`, `azure-hybrid`
* Wire `cli.main:init()` and `scaffold/project_init.py`
* Log CLI activity to shared logger

**Checkpoint:** Prints scaffold info for `--stack fastapi`

---

### Day 2 (Tuesday): Template Engine + FastAPI AzureBootstrap

**Goal:** Render FastAPI templates and create reusable template system.

* Create `templates/hybrid/fastapi/`
* Implement `render_folder(template_dir, dest_dir, context)`
* Generate `.env`, `Dockerfile`, `main.py`, `routes.py`, `requirements.txt`
* Confirm `uvicorn main:app` boots correctly

**Checkpoint:** FastAPI app boots from generated folder

---

### Day 3 (Wednesday): Django Scaffold + AAD Auth Stub

**Goal:** Scaffold Django project with optional Azure AD login.

* Create `templates/hybrid/django/`
* Generate `manage.py`, `settings.py`, `urls.py`, `wsgi.py`
* Add AAD login block via `django-auth-adfs` (toggleable)
* Reuse shared `.env` format

**Checkpoint:** Django admin boots and integrates optional AAD

---

### Day 4 (Thursday): Shared Env + PostgreSQL + MilesLib Core

**Goal:** Unify environment handling and database connectivity.

* Generate `shared/config.json`, `shared/mileslib/`
* Scaffold `.env` with `DATABASE_URL`, `SECRET_KEY`, `ENV`
* Add Docker config for PostgreSQL
* Create `env_util.py` to load/validate env vars
* Confirm DB connection works across both apps

**Checkpoint:** Apps connect to shared PostgreSQL via `.env`

---

### Day 5 (Friday): Tests, Docs, Optional Extras

**Goal:** Polish UX, support optional Redis/Celery, finalize docs/tests.

* Add `--extras redis,celery` toggle
* Generate `celery.py`, `redis.py`, background route stubs
* Add pytest tests for CLI generation
* Validate re-run behavior (idempotent)
* Document full stack in README + usage examples

**Checkpoint:** `mileslib init <name> --stack azure-hybrid --extras redis,celery` generates fully bootable backend

✅ Already Done (Sprint 2, Days 1–3)
mileslib init CLI: generates Django scaffold with .env, settings.toml, diagnostics, and global.py.

Azure AD stubbed via diagnostics scaffold.

.env supports PostgreSQL, AAD.

Centralized logger.

🔧 Remaining Sprint 2 Tasks
Day 4 – Shared Env + PostgreSQL Integration

 Inject DATABASE_URL into .env

 Add Docker support for PostgreSQL (already partially scaffolded)

 Write env_util.py to load/validate .env

 Confirm Django can connect to the PostgreSQL container

Day 5 – Extras + Tests

 Add optional --extras redis,celery support

 Scaffold celery.py, redis.py, and background_tasks.py

 Add pytest coverage for CLI + diagnostics

 Validate idempotent behavior if mileslib init is rerun

 Extend README.md with stack usage

🚀 Sprint 3: Azure Deployment Pipeline
 Azure App Services deployment configs for Django

 PostgreSQL .env integration confirmed in cloud env

 Set up HTTPS via Azure Front Door (just infra config)

 Add Front Door routing config: /admin → Django

 Create /healthz/ endpoint in Django

 Draft CI/CD script (GitHub Actions or manual deployment)

 Create internal deployment doc

🛠️ Integrate Remaining Infrastructure Feasibility Breakdown
These can be rolled in during Sprint 3 or at the tail end of Sprint 2 Day 5:

 Static storage: Use django-storages + Azure Blob + config in .env

 Secrets mgmt: Add optional Azure Key Vault integration

 Email: Scaffold EMAIL_BACKEND, document .env vars

 Monitoring: Add support for Sentry or Azure App Insights

 Admin lockdown: Restrict admin view by IP or group

 CORS/CSRF: Scaffold and configure django-cors-headers

 Rate limiting: Optional middleware integration (e.g. django-ratelimit)

 Backup strategy: Add pg_dump cron or Azure DB backup hook

 Session storage: Optional Redis backend support via django-redis


