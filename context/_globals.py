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

# ─── Default ENV Content ─────────────────────────────────────────
ENV_CONTENT = {
    "global_root": str(GLOBAL_ROOT),
    "global_cfg_file": str(GLOBAL_CFG_FILE),
    "global_log_folder": str(GLOBAL_LOG_DIR),
}

# ─── Default Global Config Values ───────────────────────────────
GLOBAL_CFG_DEFAULT = {
    "selected_project_name": None,
    "selected_project_path": None,
    "template_directory": str(GLOBAL_TEMPLATES_DIR)
}

project_name = None
project_root = None

PROJECT_CFG_DEFAULT = {
    "project_name": project_name,
    "project_root": project_root,
    "database": {
        "host": "localhost",
        "port": "5432",
    },
    "aad": {
    },
}

# ─── Required Keys for Validation ──────────────────────────────
GLOBAL_CFG_ENSURE_LIST = list(GLOBAL_CFG_DEFAULT.keys())
PROJECT_CFG_ENSURE_LIST = list(PROJECT_CFG_DEFAULT.keys())
DENY_LIST: list = ["", None, "null", "NULL", "None", "missing", "undefined", "todo"]