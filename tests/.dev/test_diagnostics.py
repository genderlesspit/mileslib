from pathlib import Path
from typing import Callable, Dict, Tuple
import re
from mileslib_core import StaticMethods as sm

CheckFn = Callable[[Dict], Tuple[str, str]]
RepairFn = Callable[[Dict], None]

DIAGNOSTICS: Dict[str, Dict[str, Callable]] = {}

def register_diagnostic(name: str, check: CheckFn, repair: RepairFn = None):
    DIAGNOSTICS[name] = {"check": check, "repair": repair}

def run_all(ctx: Dict, auto_repair: bool = False) -> int:
    print(f"[diagnostic] Running diagnostics for {ctx['project']} at {ctx['project_path']}")
    errors = 0
    for name, funcs in DIAGNOSTICS.items():
        try:
            status, msg = funcs["check"](ctx)
        except Exception as e:
            status, msg = "fail", f"Check exception: {e}"

        prefix = {"ok": "[ok]", "warn": "[warn]", "fail": "[fail]"}.get(status, "[?]")
        print(f"{prefix} {name}: {msg}")

        if status == "fail":
            errors += 1
            if auto_repair and funcs.get("repair"):
                try:
                    funcs["repair"](ctx)
                    print(f"[repair] {name} auto-repair attempted.")
                except Exception as e:
                    print(f"[repair-fail] {name}: {e}")
    return errors

def check_root_config(ctx):
    root = ctx["project_path"]
    return ("ok", "Found project root") if root.exists() else ("fail", "Project root directory missing")

def check_config_dir(ctx):
    cfg = ctx["project_path"] / "_config"
    return ("ok", "_config found") if cfg.exists() else ("fail", "_config missing")

def check_dotenv_file(ctx):
    env = ctx["project_path"] / "_config" / ".env"
    return ("ok", ".env found") if env.exists() else ("fail", ".env file missing")

def check_logs_dir(ctx):
    logs = ctx["project_path"] / "_logs"
    return ("ok", "_logs found") if logs.exists() else ("fail", "_logs directory missing")

def check_tmp_dir(ctx):
    tmp = ctx["project_path"] / ".tmp"
    return ("ok", ".tmp found") if tmp.exists() else ("fail", ".tmp directory missing")

def check_settings_file(ctx):
    sp = ctx["project_path"] / f"{ctx['project']}_core" / "settings.py"
    return ("ok", "settings.py found") if sp.exists() else ("fail", "settings.py not found")

def check_urls_file(ctx):
    up = ctx["project_path"] / f"{ctx['project']}_core" / "urls.py"
    return ("ok", "urls.py found") if up.exists() else ("fail", "urls.py not found")

def check_global_py(ctx):
    gp = ctx["project_path"] / "global.py"
    return ("ok", "global.py found") if gp.exists() else ("fail", "global.py missing")

def check_auth_adfs_settings(ctx):
    sp = ctx["project_path"] / f"{ctx['project']}_core" / "settings.py"
    if not sp.exists():
        return "fail", "settings.py not found"
    content = sp.read_text()
    if "django_auth_adfs" not in content:
        return "fail", "'django_auth_adfs' not in INSTALLED_APPS"
    if "AUTH_ADFS" not in content:
        return "fail", "AUTH_ADFS config not found"
    return "ok", "AAD config present in settings.py"

def check_adfs_route(ctx):
    up = ctx["project_path"] / f"{ctx['project']}_core" / "urls.py"
    if not up.exists():
        return "fail", "urls.py not found"
    content = up.read_text()
    return (
        "ok", "AAD route included"
        if "django_auth_adfs.urls" in content else
        ("fail", "oauth2/ route not registered")
    )

def check_env_vars_aad(ctx):
    env = sm.FileIO.read(ctx["project_path"] / "_config" / ".env", ext="env")
    required = ["AAD_SERVER", "AAD_CLIENT_ID", "AAD_TENANT_ID"]
    missing = [k for k in required if not env.get(k) or "<" in env[k]]
    return (
        "ok", "All AAD env vars set"
        if not missing else
        ("warn", f"Missing/incomplete AAD vars: {', '.join(missing)}")
    )

def check_env_vars_db(ctx):
    env = sm.FileIO.read(ctx["project_path"] / "_config" / ".env", ext="env")
    required = ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASS"]
    missing = [k for k in required if not env.get(k)]
    return (
        "ok", "All DB env vars set"
        if not missing else
        ("warn", f"Missing DB vars: {', '.join(missing)}")
    )

def check_requirements(ctx):
    rp = ctx["project_path"] / "requirements.txt"
    if not rp.exists():
        return "fail", "requirements.txt not found"
    content = rp.read_text()
    required = ["Django", "psycopg2", "python-dotenv", "django-auth-adfs"]
    missing = [pkg for pkg in required if pkg.lower() not in content.lower()]
    return (
        "ok", "All required packages present"
        if not missing else
        ("warn", f"Missing dependencies in requirements.txt: {', '.join(missing)}")
    )

from .project_diagnostic import register_diagnostic

# Register all diagnostic checks
register_diagnostic("Root Directory", check_root_config)
register_diagnostic("_config Directory", check_config_dir)
register_diagnostic(".env File", check_dotenv_file)
register_diagnostic("_logs Directory", check_logs_dir)
register_diagnostic(".tmp Directory", check_tmp_dir)

register_diagnostic("settings.py Present", check_settings_file)
register_diagnostic("urls.py Present", check_urls_file)
register_diagnostic("global.py Present", check_global_py)

register_diagnostic("AAD Settings", check_auth_adfs_settings)
register_diagnostic("AAD Login Route", check_adfs_route)

register_diagnostic("AAD Env Vars", check_env_vars_aad)
register_diagnostic("DB Env Vars", check_env_vars_db)

register_diagnostic("Requirements.txt Check", check_requirements)
