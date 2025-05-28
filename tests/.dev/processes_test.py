import os
import shutil
import subprocess
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

import os
import uvicorn
import click
import msal
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from threading import Thread
from datetime import datetime
from mileslib_core import BackendMethods as bm
from mileslib_core import mileslib_cli

class InitializeProject:
    @staticmethod
    @mileslib(label="init_project", retry=True)
    @mileslib_cli(project_only=False)  # or True, depending on scope
    def init_project(ctx, project_name: str):
        """
        Initializes a new project folder with Django scaffold and config.

        Args:
            project_name (str): Name of the project.

        Raises:
            click.Abort: On validation or subprocess failure.
        """

        # ─── Path Setup ─────────────────────────────────────────────
        try:
            root = sm.validate_directory(ROOT / project_name)
            proj_root = sm.validate_directory(root)
            proj_str = str(proj_root)
        except Exception as e:
            print(f"[init] Directory validation failed: {e}")
            raise click.Abort()

        cfg_path = root / f"mileslib_{project_name}_settings.toml"
        cfg = mc.Config.build(cfg_path)
        tests = root / "_tests"
        django_name = f"{project_name}_core"
        db_name = f"{project_name}_db"
        proj_details_list = {
            "project_name": project_name,
            "proj_root": proj_root,
            "config_dir": cfg,
            "tests_dir": tests,
            "django_project": django_name,
            "database_name": db_name,
        }
        proj_details = mc.Config.configify(proj_details_list)

        # ─── Django ────────────────────────────────────────────────
        def init_django():
            print("[init] Starting Django scaffold...")
            subprocess.run(
                ["python", "-m", "django", "startproject", django_name, proj_root],
                check=True
            )

        # ─── Folders ───────────────────────────────────────────────
        def init_folders():
            for d in [root, tests]:
                sm.validate_directory(d)

        # ─── Config (.toml) ─────────────────────────────────────────
        def init_config():
            mc.cfg_write(path=cfg,add=proj_details)

        # ─── Gitignore / Requirements / Readme ──────────────────────
        def scaffold_basics():
            (proj_root / ".gitignore").write_text(textwrap.dedent("""\
                __pycache__/
                *.pyc
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
            """), encoding="utf-8")

            (proj_root / "requirements.txt").write_text(textwrap.dedent("""\
                #
                """), encoding="utf-8")

            (proj_root / "README.md").write_text(f"# {project_name}\n\nInitialized with MilesLib.\n", encoding="utf-8")

        try:
            init_django()
            init_folders()
            init_config()
            scaffold_basics()
            print(f"[init] Project '{project_name}' created successfully.")
        except Exception as e:
            print(f"[error] Initialization failed: {e}")
            if root.exists():
                shutil.rmtree(root)
            raise click.Abort()

app = FastAPI()

class AzureBootstrap:
    #project_name = click_ctx
    class Consent:
        @staticmethod
        def user_has_consented() -> bool:
            return False  # Replace with local registry or project config check

        @staticmethod
        def redirect_to_admin_consent():
            tenant_id = bm.Secrets.get("BOOTSTRAP_TENANT_ID")
            client_id = bm.Secrets.get("BOOTSTRAP_CLIENT_ID")
            redirect_uri = bm.Secrets.get("REDIRECT_URI")

            url = (
                f"https://login.microsoftonline.com/{tenant_id}/adminconsent"
                f"?client_id={client_id}&redirect_uri={redirect_uri}"
            )
            click.launch(url)

        @staticmethod
        def wait_for_callback():
            Thread(target=lambda: uvicorn.run(app, port=8000, log_level="warning")).start()
            click.echo("Waiting for admin consent callback...")

    class MSALClient:
        @staticmethod
        def get_token():
            tenant_id = bm.Secrets.get("BOOTSTRAP_TENANT_ID")
            client_id = bm.Secrets.get("BOOTSTRAP_CLIENT_ID")
            client_secret = bm.Secrets.get("BOOTSTRAP_CLIENT_SECRET")

            app = msal.ConfidentialClientApplication(
                client_id=client_id,
                authority=f"https://login.microsoftonline.com/{tenant_id}",
                client_credential=client_secret
            )

            token = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
            return token["access_token"]

    class AAD:
        @staticmethod
        def register_app(display_name: str) -> tuple[str, str]:
            token = AzureBootstrap.MSALClient.get_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            payload = {
                "displayName": display_name,
                "signInAudience": "AzureADMyOrg"
            }

            resp = bm.http_post("https://graph.microsoft.com/v1.0/applications", payload)
            data = resp.json()
            return data["appId"], data["id"]

        @staticmethod
        def add_client_secret(object_id: str) -> str:
            token = AzureBootstrap.MSALClient.get_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            payload = {
                "passwordCredential": {
                    "displayName": "AutoGenSecret"
                }
            }

            resp = bm.http_post(
                f"https://graph.microsoft.com/v1.0/applications/{object_id}/addPassword",
                payload
            )
            return resp.json()["secretText"]

    class Vault:
        @staticmethod
        def store_secrets(app_id: str, secret: str, tenant_id: str):
            bm.Secrets.set("aad-app-id", app_id)
            bm.Secrets.set("aad-app-secret", secret)
            bm.Secrets.set("aad-tenant-id", tenant_id)

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
# FastAPI Callback for AAD Admin Consent
@app.get("/callback")
def handle_callback(request: Request):
    if request.query_params.get("admin_consent") == "True":
        tenant_id = request.query_params.get("tenant")
        AzureBootstrap.Registry.update(tenant_id)
        return PlainTextResponse("Consent successful! You may now close this window.")
    return PlainTextResponse("Consent failed or denied.")
