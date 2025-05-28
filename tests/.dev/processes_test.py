import os
import textwrap
from pathlib import Path

from jinja2 import FileSystemLoader, select_autoescape
from msilib.schema import Environment

import msal
import click
import uvicorn
import requests
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from datetime import datetime
from threading import Thread
from webbrowser import open_new_tab
from mileslib_core import sm, mc, mileslib
import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient



app = FastAPI()

class AzureBootstrap:

    class Consent:
        @staticmethod
        def user_has_consented() -> bool:
            # Placeholder: check local state or config file
            return False

        @staticmethod
        def redirect_to_admin_consent():
            tenant_id = os.getenv("BOOTSTRAP_TENANT_ID")
            client_id = os.getenv("BOOTSTRAP_CLIENT_ID")
            redirect_uri = os.getenv("REDIRECT_URI")
            url = (
                f"https://login.microsoftonline.com/{tenant_id}/adminconsent"
                f"?client_id={client_id}&redirect_uri={redirect_uri}"
            )
            open_new_tab(url)

        @staticmethod
        def wait_for_callback():
            Thread(target=lambda: uvicorn.run(app, port=8000)).start()
            click.echo("Waiting for admin consent callback...")

    class MSALClient:
        @staticmethod
        def get_token():
            tenant_id = os.getenv("BOOTSTRAP_TENANT_ID")
            client_id = os.getenv("BOOTSTRAP_CLIENT_ID")
            client_secret = os.getenv("BOOTSTRAP_CLIENT_SECRET")
            app = msal.ConfidentialClientApplication(
                client_id=client_id,
                authority=f"https://login.microsoftonline.com/{tenant_id}",
                client_credential=client_secret
            )
            token = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
            return token["access_token"]

    class AAD:
        @staticmethod
        def register_app(display_name: str):
            token = AzureBootstrap.MSALClient.get_token()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            payload = {"displayName": display_name, "signInAudience": "AzureADMyOrg"}
            response = requests.post("https://graph.microsoft.com/v1.0/applications", headers=headers, json=payload)
            data = response.json()
            return data["appId"], data["id"]

        @staticmethod
        def add_client_secret(object_id: str):
            token = AzureBootstrap.MSALClient.get_token()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            payload = {"passwordCredential": {"displayName": "AutoGenSecret"}}
            response = requests.post(
                f"https://graph.microsoft.com/v1.0/applications/{object_id}/addPassword",
                headers=headers, json=payload
            )
            return response.json()["secretText"]

    class Vault:
        @staticmethod
        def store(app_id: str, secret: str, tenant_id: str):
            vault_url = os.getenv("KEY_VAULT_URL")
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=vault_url, credential=credential)
            client.set_secret("aad-app-id", app_id)
            client.set_secret("aad-app-secret", secret)
            client.set_secret("aad-tenant-id", tenant_id)

    class Registry:
        tenants_db = {}

        @staticmethod
        def update(tenant_id: str):
            AzureBootstrap.Registry.tenants_db[tenant_id] = {
                "consented": True,
                "created_at": datetime.utcnow().isoformat(),
                "apps": []
            }

# ────────────────────────────────────────────────
# FastAPI Route for Consent Redirect
@app.get("/callback")
def handle_callback(request: Request):
    if request.query_params.get("admin_consent") == "True":
        tenant_id = request.query_params.get("tenant")
        AzureBootstrap.Registry.update(tenant_id)
        return PlainTextResponse("Consent successful! You may now use the app.")
    return PlainTextResponse("Consent failed or denied.")

# ────────────────────────────────────────────────
# CLI Entry Point
@click.command()
def bootstrap():
    if not AzureBootstrap.Consent.user_has_consented():
        AzureBootstrap.Consent.redirect_to_admin_consent()
        AzureBootstrap.Consent.wait_for_callback()
        return

    app_id, object_id = AzureBootstrap.AAD.register_app("MyServiceApp")
    secret = AzureBootstrap.AAD.add_client_secret(object_id)
    AzureBootstrap.Vault.store(app_id, secret, os.getenv("BOOTSTRAP_TENANT_ID"))
    click.echo(f"[SUCCESS] App Registered: {app_id}")


if __name__ == "__main__":
    bootstrap()

    class Methods:
        @staticmethod
        d

        class Diagnostics:
            """
            Centralized diagnostic runner for MilesLib project scaffolds.

            Each diagnostic is defined by a label and a pair of callable strings:
            - Checks must return a (status, message) tuple
            - Repairs are optional and invoked if `--repair` is passed

            Future-proof design:
            - All checks live under Diagnostics.Checks
            - All repairs live under Diagnostics.Repairs
            - Mapping is declarative in Diagnostics.MAP
            """

            DIAGNOSTICS: Dict[str, Dict[str, Callable]] = {}

            MAP: Dict[str, Tuple[str, Optional[str]]] = {
                "Check: _config dir": ("config_dir", "config_dir"),
                "Check: .env file": ("dotenv_file", "dotenv_file"),
                "Check: settings.py": ("settings_file", None),
                "Check: urls.py": ("urls_file", None),
                "Check: global.py": ("global_py", None),
                "Check: AAD settings.py": ("auth_adfs_settings", "auth_adfs_settings"),
            }

            @staticmethod
            def register(label: str, check_fn: Callable, repair_fn: Optional[Callable] = None):
                CLI.Project.Diagnostics.DIAGNOSTICS[label] = {
                    "check": check_fn,
                    "repair": repair_fn,
                }

            @staticmethod
            def run():
                for label, (check_name, repair_name) in CLI.Project.Diagnostics.MAP.items():
                    check_fn = getattr(CLI.Project.Diagnostics.Checks, check_name)
                    repair_fn = getattr(CLI.Project.Diagnostics.Repairs, repair_name) if repair_name else None
                    CLI.Project.Diagnostics.register(label, check_fn, repair_fn)

            @staticmethod
            def run_all(ctx: dict, auto_repair: bool = False) -> int:
                click.echo(f"[diagnostic] Running diagnostics for {ctx['project']} at {ctx['project_path']}")
                errors = 0

                for label, funcs in CLI.Project.Diagnostics.DIAGNOSTICS.items():
                    try:
                        status, msg = funcs["check"](ctx)
                    except Exception as e:
                        status, msg = "fail", f"Check exception: {e}"

                    prefix = {"ok": "[ok]", "warn": "[warn]", "fail": "[fail]"}.get(status, "[?]")
                    click.echo(f"{prefix} {label}: {msg}")

                    if status == "fail":
                        if auto_repair and funcs.get("repair"):
                            try:
                                funcs["repair"](ctx)
                                click.echo(f"[repair] {label} auto-repair attempted.")

                                # Rerun the check after repair
                                status, msg = funcs["check"](ctx)
                                prefix = {"ok": "[ok]", "warn": "[warn]", "fail": "[fail]"}.get(status, "[?]")
                                click.echo(f"{prefix} {label} (after repair): {msg}")
                            except Exception as e:
                                click.echo(f"[repair-fail] {label}: {e}")
                                status = "fail"

                        # Final error count after re-check
                        if status == "fail":
                            errors += 1

                return errors

            class Checks:
                @staticmethod
                def config_dir(ctx):
                    path = ctx["project_path"] / "_config"
                    return ("ok", "_config directory found") if path.exists() else ("fail", "_config directory missing")

                @staticmethod
                def dotenv_file(ctx):
                    path = ctx["project_path"] / "_config" / ".env"
                    return ("ok", ".env file found") if path.exists() else ("fail", ".env file missing")

                @staticmethod
                def settings_file(ctx):
                    path = ctx["project_path"] / f"{ctx['project']}_core" / "settings.py"
                    return ("ok", "settings.py found") if path.exists() else ("fail", "settings.py missing")

                @staticmethod
                def urls_file(ctx):
                    path = ctx["project_path"] / f"{ctx['project']}_core" / "urls.py"
                    return ("ok", "urls.py found") if path.exists() else ("fail", "urls.py missing")

                @staticmethod
                def global_py(ctx):
                    path = ctx["project_path"] / "global.py"
                    return ("ok", "global.py found") if path.exists() else ("fail", "global.py missing")

                @staticmethod
                def auth_adfs_settings(ctx):
                    sp = ctx["project_path"] / f"{ctx['project']}_core" / "settings.py"
                    if not sp.exists():
                        return "fail", "settings.py not found"
                    content = sp.read_text()
                    if "django_auth_adfs" not in content:
                        return "fail", "'django_auth_adfs' not in INSTALLED_APPS"
                    if "AUTH_ADFS" not in content:
                        return "fail", "AUTH_ADFS block missing"
                    return "ok", "AAD config present"

            class Repairs:
                @staticmethod
                def config_dir(ctx):
                    path = ctx["project_path"] / "_config"
                    path.mkdir(parents=True, exist_ok=True)

                @staticmethod
                def dotenv_file(ctx):
                    path = ctx["project_path"] / "_config" / ".env"
                    if not path.exists():
                        path.write_text("DB_HOST=localhost\n")

                @staticmethod
                def auth_adfs_settings(ctx):
                    sp = ctx["project_path"] / f"{ctx['project']}_core" / "settings.py"
                    if not sp.exists():
                        raise FileNotFoundError("settings.py missing")

                    content = sp.read_text()
                    backup = sp.with_name("settings.py.bak")
                    backup.write_text(content)

                    modified = content
                    if "django_auth_adfs" not in content:
                        modified = modified.replace("INSTALLED_APPS = [", "INSTALLED_APPS = [\n    'django_auth_adfs',")

                    if "AUTH_ADFS" not in content:
                        modified += """

        # --- Auto-injected by MilesLib diagnostics ---
        AUTH_ADFS = {
            "AUDIENCE": os.getenv("AAD_CLIENT_ID"),
            "CLIENT_ID": os.getenv("AAD_CLIENT_ID"),
            "CLIENT_SECRET": os.getenv("AAD_CLIENT_SECRET"),
            "TENANT_ID": os.getenv("AAD_TENANT_ID"),
            "AUTHORITY": f"https://login.microsoftonline.com/{os.getenv('AAD_TENANT_ID')}",
            "REDIRECT_URI": os.getenv("AAD_REDIRECT_URI", "http://localhost:8000/oauth2/login/"),
            "RELYING_PARTY_ID": os.getenv("AAD_CLIENT_ID"),
            "CLAIM_MAPPING": {"first_name": "given_name", "last_name": "family_name", "email": "upn"},
            "USERNAME_CLAIM": "upn",
            "GROUP_CLAIM": "roles",
            "LOGIN_EXEMPT_URLS": [r"^healthz/$"],
        }
        """
                    sp.write_text(modified)

class Initialize_Project:
    @staticmethod
    def init_project(project_name: str):
        """
        Create a new project folder with default structure and Django scaffold.

        Args:
            project_name (str): Name of the project to be created.

        Side Effects:
            - Creates folders: _config, _tests, _logs, .tmp
            - Writes a default settings.toml config file
            - Runs `django-admin startproject`

        Raises:
            RuntimeError: If root is not initialized.
            subprocess.CalledProcessError: If Django project creation fails.
        """

        # Validate Directory
        click.echo("[debug] Validating Directory ...")
        try:
            root = Directory.validate() / project_name
            click.echo(f"[debug] {root} successfully identified as project root.")
        except Exception as e:
            click.echo(f"[validate error]: {e}")
            raise click.Abort

        proj_root = sm.validate_directory(root)
        proj_root_str = repr(str(proj_root))
        absolute_path_str = repr(str(Directory.absolute_path))

        cfg = root / "_config"
        tests = root / "_tests"
        logs = root / "_logs"
        tmp = root / ".tmp"
        django_name = f"{project_name}_core"

        def init_django():
            click.echo("[init] Initializing Django project...")
            subprocess.run(
                ["python", "-m", "django", "startproject", django_name, proj_root],
                check=True
            )

        def init_directories():
            click.echo(f"[init] Creating directories for '{project_name}'...")
            for d in [root, cfg, tests, logs, tmp]:
                sm.validate_directory(d)

        def init_config():
            click.echo("[init] Writing default configuration...")
            db_name = f"{project_name}_db"

            sm.cfg_write(
                pdir=root,
                file_name="settings.toml",
                data={
                    "valid": True,
                    "project": project_name,
                    "database_name": db_name,
                    "env": {"active": "default"},

                    "paths": {
                        "absolute_root": str(Directory.absolute_path),
                        "project_root": str(proj_root),
                        "config": str(cfg),
                        "logs": str(logs),
                        "tmp": str(tmp),
                    },

                    "database": {
                        "engine": "postgresql",
                        "host": "${DB_HOST}",
                        "port": "${DB_PORT}",
                        "name": "${DB_NAME}",
                        "user": "${DB_USER}",
                        "password": "${DB_PASS}",
                    },

                    "aad": {
                        "server": "${AAD_SERVER}",
                        "client_id": "${AAD_CLIENT_ID}",
                        "client_secret": "${AAD_CLIENT_SECRET}",  # Optional, for confidential apps
                        "tenant_id": "${AAD_TENANT_ID}",
                        "scopes": "${AAD_SCOPES}",
                        "authority": "https://login.microsoftonline.com/${AAD_TENANT_ID}",
                        "redirect_uri": "http://localhost:8000/oauth2/login/",  # can override per env
                    }
                },
                overwrite=False,
                replace_existing=False
            )

        def init_env():
            db_name = f"{project_name}_db"
            env_data = {
                "DB_HOST": "localhost",
                "DB_PORT": "5432",
                "DB_NAME": db_name,
                "DB_USER": "admin",
                "DB_PASS": "changeme",

                "AAD_SERVER": "login.microsoftonline.com/<tenant-id>",
                "AAD_CLIENT_ID": "<your-client-id-guid>",
                "AAD_CLIENT_SECRET": "<your-secret>",  # if using client credentials flow
                "AAD_TENANT_ID": "<your-tenant-guid>",
                "AAD_SCOPES": "User.Read openid profile offline_access"
            }

            sm.FileIO.write(
                path=cfg / ".env",
                ext="env",
                data=env_data,
                overwrite=True,
                replace_existing=True
            )
            env_file = sm.validate_file(path=Path(cfg / ".env"))
            if env_file.exists() is False:
                raise FileNotFoundError("Could not locate .env file!")
            env_read = sm.FileIO.read(env_file, ext="env")
            if env_read is None:
                raise AttributeError("Failed to write to .env file!")

        def init_global_variables():
            """Write a global.py file that exposes project constants for DB, AAD, and project paths."""
            global_file = proj_root / "global.py"

            content = textwrap.dedent(f"""\
                            from pathlib import Path
                            import os
                            from dotenv import load_dotenv
                            from mileslib import StaticMethods as sm

                            # Auto-generated by MilesLib init_project

                            # === Load .env ===
                            dotenv_path = Path(__file__).parent / ".env"
                            load_dotenv(dotenv_path=dotenv_path)

                            # === PostgreSQL Configuration ===
                            DB_HOST = os.getenv("DB_HOST", "localhost")
                            DB_PORT = os.getenv("DB_PORT", "5432")
                            DB_NAME = os.getenv("DB_NAME", "")
                            DB_USER = os.getenv("DB_USER", "")
                            DB_PASS = os.getenv("DB_PASS", "")

                            # === Azure Active Directory / MSAL Configuration ===
                            AAD_SERVER = os.getenv("AAD_SERVER")  # e.g., login.microsoftonline.com/<tenant-id>
                            AAD_CLIENT_ID = os.getenv("AAD_CLIENT_ID")  # Azure AD App Client ID
                            AAD_CLIENT_SECRET = os.getenv("AAD_CLIENT_SECRET")  # Optional for confidential apps
                            AAD_TENANT_ID = os.getenv("AAD_TENANT_ID")  # Used to build authority
                            AAD_SCOPES = os.getenv("AAD_SCOPES", "User.Read")  # space-separated or comma-separated scopes
                            AAD_AUTHORITY = f"https://login.microsoftonline.com/{{AAD_TENANT_ID}}" if AAD_TENANT_ID else None

                            # === Project Paths ===
                            ABSOLUTE_ROOT = Path(
                                sm.cfg_get('absolute_root', pdir={absolute_path_str}, section='paths')
                            )
                            PROJECT_ROOT = Path(
                                sm.cfg_get('project_root', pdir={proj_root_str}, section='paths')
                            )
                        """)

            global_file.write_text(content, encoding="utf-8")
            print(f"[init] Wrote global constants to {global_file}")

        def acknowledge_project():
            click.echo("[init] Acknowledging project globally...")
            sm.cfg_write(
                pdir=Directory.absolute_path,
                file_name="mileslib_config.toml",
                data={
                    f"{project_name}": str(proj_root)
                },
                section="active_projects"
            )

        def scaffold_gitignore():
            """Generate a default .gitignore file for Python/Django projects."""
            gitignore_path = proj_root / ".gitignore"
            if gitignore_path.exists():
                print(f"[gitignore] .gitignore already exists. Skipping.")
                return

            content = textwrap.dedent("""\
                            __pycache__/
                            *.pyc
                            *.pyo
                            *.log
                            .env
                            .DS_Store
                            db.sqlite3
                            /postgres_data/
                            /tmp/
                            .pytest_cache/
                            .venv/
                            .mypy_cache/
                            *.sqlite3
                        """)
            gitignore_path.write_text(content, encoding="utf-8")
            print(f"[gitignore] Generated .gitignore")

        def scaffold_requirements():
            """Create a minimal requirements.txt if one doesn't exist."""
            req_path = proj_root / "requirements.txt"
            if req_path.exists():
                print("[req] requirements.txt already exists. Skipping.")
                return

            content = textwrap.dedent("""\
                            Django>=4.2
                            psycopg2-binary
                            python-dotenv
                        """)
            req_path.write_text(content, encoding="utf-8")
            print(f"[req] Generated requirements.txt")

        def scaffold_readme():
            """Create a starter README.md for the project."""
            readme_path = proj_root / "README.md"
            if readme_path.exists():
                print("[readme] README.md already exists. Skipping.")
                return

            content = textwrap.dedent("""\
                            Django>=4.2
                            psycopg2-binary
                            python-dotenv
                            django-auth-adfs  # AAD support
                            msal  # Optional: for other MSAL-based auth
                        """)
            readme_path.write_text(content, encoding="utf-8")
            print(f"[readme] Generated README.md")

        try:
            init_django()
            init_directories()
            init_config()
            init_env()
            init_global_variables()
            acknowledge_project()

            scaffold_gitignore()
            scaffold_requirements()
            scaffold_readme()

        except Exception as e:
            click.echo(f"[error] {project_name} initialization failed!: {e}")
            if root.exists():
                shutil.rmtree(root)
            click.echo("[abort] Setup aborted.")
            exit(1)

