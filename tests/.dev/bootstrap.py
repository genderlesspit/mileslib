import os
import uvicorn
import click
import msal
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from threading import Thread
from datetime import datetime
from mileslib_core import BackendMethods as bm

app = FastAPI()

class AzureBootstrap:

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

# ────────────────────────────────────────────────
# CLI Bootstrap Entry
@click.command()
def bootstrap():
    bm.Secrets.clear_cache()
    bm.Secrets.load_vault()  # Initializes vault client and uses mc.env

    if not AzureBootstrap.Consent.user_has_consented():
        AzureBootstrap.Consent.redirect_to_admin_consent()
        AzureBootstrap.Consent.wait_for_callback()
        return

    app_id, object_id = AzureBootstrap.AAD.register_app("MyServiceApp")
    secret = AzureBootstrap.AAD.add_client_secret(object_id)
    tenant_id = bm.Secrets.get("BOOTSTRAP_TENANT_ID")

    AzureBootstrap.Vault.store_secrets(app_id, secret, tenant_id)
    click.echo(f"[SUCCESS] App registered: {app_id}")

    bm.Secrets.clear_cache()
