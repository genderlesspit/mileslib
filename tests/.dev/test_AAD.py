import os
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

app = FastAPI()

class Bootstrap:

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
            token = Bootstrap.MSALClient.get_token()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            payload = {"displayName": display_name, "signInAudience": "AzureADMyOrg"}
            response = requests.post("https://graph.microsoft.com/v1.0/applications", headers=headers, json=payload)
            data = response.json()
            return data["appId"], data["id"]

        @staticmethod
        def add_client_secret(object_id: str):
            token = Bootstrap.MSALClient.get_token()
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
            Bootstrap.Registry.tenants_db[tenant_id] = {
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
        Bootstrap.Registry.update(tenant_id)
        return PlainTextResponse("Consent successful! You may now use the app.")
    return PlainTextResponse("Consent failed or denied.")

# ────────────────────────────────────────────────
# CLI Entry Point
@click.command()
def bootstrap():
    if not Bootstrap.Consent.user_has_consented():
        Bootstrap.Consent.redirect_to_admin_consent()
        Bootstrap.Consent.wait_for_callback()
        return

    app_id, object_id = Bootstrap.AAD.register_app("MyServiceApp")
    secret = Bootstrap.AAD.add_client_secret(object_id)
    Bootstrap.Vault.store(app_id, secret, os.getenv("BOOTSTRAP_TENANT_ID"))
    click.echo(f"[SUCCESS] App Registered: {app_id}")


if __name__ == "__main__":
    bootstrap()
