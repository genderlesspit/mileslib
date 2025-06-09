import os
from pathlib import Path

# ─── Root Directory ──────────────────────────────────────────────
GLOBAL_ROOT = Path(os.getcwd()).resolve()

# ─── Config and Log Paths ────────────────────────────────────────
GLOBAL_CFG_FILE = GLOBAL_ROOT / "mileslib_settings.toml"
GLOBAL_CFG_FILE.parent.mkdir(parents=True, exist_ok=True)  # Ensure config dir exists
GLOBAL_LOG_DIR = GLOBAL_ROOT / "logs"
GLOBAL_LOG_DIR.mkdir(parents=True, exist_ok=True)  # Ensure log dir exists
GLOBAL_TEMPLATES_DIR = GLOBAL_ROOT / "templates"

# ─── Environment Paths ───────────────────────────────────────────
DEF_ENV = GLOBAL_ROOT / ".env"
SEL_ENV = None
ENV = SEL_ENV if SEL_ENV is not None else DEF_ENV