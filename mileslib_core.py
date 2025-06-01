import builtins
import contextvars
import shlex
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from unittest import mock
from urllib.parse import urlparse
import subprocess
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.core.exceptions import ResourceExistsError
import shutil
import subprocess
import platform
import msal
import pytest
import importlib.util
import requests
import toml
from typing import Any, List, Union, Callable, Tuple, Type, Optional, Dict
from types import ModuleType, SimpleNamespace
import json
import importlib.util
import subprocess
import time
from pathlib import Path
import tempfile
from datetime import datetime
import psutil
import yaml
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from click import Abort
from click.exceptions import Exit
from django.core.mail.message import sanitize_address
from dynaconf import Dynaconf
import click
import textwrap
from typing import TYPE_CHECKING
import threading
import inspect

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from jinja2 import Environment, select_autoescape, FileSystemLoader

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import threading
import time
import uvicorn
from functools import wraps
from typing import Callable
import ctypes

if TYPE_CHECKING:
    LOG: Any  # let IDEs think it's there

import os
import sys
import shlex
import subprocess
import platform
from shutil import which


import os
import sys
import platform
import subprocess
from shutil import which

class BackendMethods:
    from starlette.responses import JSONResponse
    from functools import wraps
    from typing import Callable





    class AzureUser:
        """
        Handles interactive login to Azure CLI, caches the result, and validates
        the authenticated account against project-scoped tenant and subscription.

        Ensures:
          - Clean login (once per session)
          - Valid tenant ID and subscription ID
        """

        _cached_user = None

        @staticmethod
        def get(project: str) -> dict:
            """
            Returns the current user context, logging in if not already cached.

            Args:
                project (str): Project name

            Returns:
                dict: Validated CLI user context
            """
            if bm.AzureUser._cached_user:
                return bm.AzureUser._cached_user

            try:
                print("[AzureUser] Attempting to reuse existing Azure CLI session...")
                context = bm.AzureUser._validate_context(project)
            except Exception as e:
                print(f"[AzureUser] Existing session invalid or missing. Reason: {e}")
                context = bm.AzureUser.login(project)

            bm.AzureUser._cached_user = context
            print(f"User context successfully retrieved!: {context}")
            return context

        @staticmethod
        def login(project: str) -> dict:
            """
            Clears token cache, prompts interactive login, and validates context.

            Args:
                project (str): Project name

            Returns:
                dict: Validated user metadata
            """
            print("[AzureUser] 🔐 Logging in via Azure CLI...")
            tenant_id = bm.AzureTenant.get(project)

            # Add the tenant ID to the az login command
            Subprocess.CMD.run(
                ["az", "login", "--tenant", tenant_id, "--use-device-code"],
                capture_output=False,
                check=True,
                force_global_shell=True
            )

            context = bm.AzureUser._validate_context(project)
            bm.AzureUser._cached_user = context
            return context

        @staticmethod
        def _validate_context(project: str) -> dict:
            """
            Validates current CLI user against tenant and subscription.

            Args:
                project (str): Project scope

            Returns:
                dict: Validated account context
            """
            tenant_id = bm.AzureTenant.get(project)
            subscription_id = bm.AzureSubscription.get(project)

            result = Subprocess.CMD.run(
                ["az", "account", "show", "--output", "json"],
                capture_output=True, text=True, check=True, force_global_shell=True
            ).stdout

            import json
            user = json.loads(result)
            actual_tenant = user.get("tenantId")
            actual_sub = user.get("id")

            if actual_tenant != tenant_id:
                raise RuntimeError(f"[AzureUser] ❌ Tenant mismatch: CLI={actual_tenant} vs Config={tenant_id}")
            if actual_sub != subscription_id:
                raise RuntimeError(f"[AzureUser] ❌ Subscription mismatch: CLI={actual_sub} vs Config={subscription_id}")

            name = user.get("user", {}).get("name", "Unknown")
            print(f"[AzureUser] ✅ Logged in as: {name} ({user.get('userType')})")

            return {
                "tenant_id": actual_tenant,
                "subscription_id": actual_sub,
                "user": user.get("user", {}),
                "raw": user
            }

        @staticmethod
        def help():
            """
            CLI guidance for Azure login and account troubleshooting.
            """
            print("\n[🧠 Azure Login Help]")
            print("──────────────────────────────")
            print("1. `az logout && az account clear` — force sign-out")
            print("2. `az login` — sign in again")
            print("3. `az account show` — inspect current identity")
            print("──────────────────────────────\n")

    class AzureClient:
        """
        Manages Azure App Registrations: either retrieves an existing app or creates a new one.
        """

        @staticmethod
        def get_app(project: str) -> dict:
            """
            Retrieves an existing app registration for the specified project or creates a new one if not found.

            Args:
                project (str): Project name, used for scoping.

            Returns:
                dict: Contains app details, including client_id and appId.
            """
            print(f"[AzureClient] Checking if app registration exists for project '{project}'...")

            # Step 1: Check if the app registration exists
            app = bm.AzureClient._find_existing_app(project)

            # Step 2: If app doesn't exist, create it
            if not app:
                print(f"[AzureClient] App registration not found for project '{project}'. Creating a new one...")
                app = bm.AzureClient.create_app(project)

            return app

        @staticmethod
        def _find_existing_app(project: str) -> dict:
            """
            Checks if an app registration already exists for the given project.

            Args:
                project (str): Project name to check for app registration.

            Returns:
                dict: App registration details if found, otherwise None.
            """
            try:
                # Correct query to get appId and displayName
                result = Subprocess.CMD.run(
                    ["az", "ad", "app", "list", "--query", "[].{appId: appId, displayName: displayName}", "--output",
                     "json"],
                    capture_output=True, text=True, check=True
                )
                apps = json.loads(result.stdout)

                # Loop through the list of apps to check for an app with a matching display name or appId
                for app in apps:
                    if project.lower() in app['displayName'].lower():  # Match the project name
                        print(f"[AzureClient] Found existing app: {app['displayName']} ({app['appId']})")
                        return app

                return None
            except subprocess.CalledProcessError as e:
                print(f"[AzureClient] Error while checking for existing app: {e}")
                print(f"stdout: {e.stdout}")
                print(f"stderr: {e.stderr}")
                return None

        @staticmethod
        def create_app(project: str) -> dict:
            """
            Creates a new Azure AD app registration for the specified project.

            Args:
                project (str): Project name used for app registration display name.

            Returns:
                dict: Newly created app details, including client_id and appId.
            """
            print(f"[AzureClient] Creating new app registration for project '{project}'...")

            try:
                result = Subprocess.CMD.run(
                    ["az", "ad", "app", "create", "--display-name", project, "--query", "appId,displayName,appId",
                     "--output", "json"],
                    capture_output=True, text=True, check=True
                )
                new_app = json.loads(result.stdout)
                print(f"[AzureClient] Created new app: {new_app['displayName']} ({new_app['appId']})")
                return new_app
            except subprocess.CalledProcessError as e:
                print(f"[AzureClient] Error creating app registration: {e}")
                print(f"stdout: {e.stdout}")
                print(f"stderr: {e.stderr}")
                raise

    class AzureResourceGroup:
        """
        Handles discovery or creation of a resource group using Azure CLI or fallback logic.

        Priority:
        - EnvLoader: {project}.RESOURCE_GROUP
        - az group list → user selection
        - fallback default: <project>-rg
        """

        @staticmethod
        def get(project: str) -> str:
            """
            Resolves the resource group for the given project.

            Args:
                project (str): Project name

            Returns:
                str: Validated or selected resource group name
            """
            key = f"{project}.RESOURCE_GROUP"
            rg = mc.env.get(key, required=False)
            if rg:
                return rg

            print(f"[AzureResourceGroup] Resolving resource group for project: {project}")

            try:
                sub_id = bm.AzureIDs.subscription_id(project)
                result = Subprocess.CMD.run([
                    "az", "group", "list",
                    "--subscription", sub_id,
                    "--query", "[].name",
                    "--output", "tsv"
                ], capture_output=True, text=True, force_global_shell=True)

                groups = result.stdout.strip().splitlines()
                if not groups:
                    raise RuntimeError("[AzureResourceGroup] No resource groups found in this subscription.")

                print(f"[AzureResourceGroup] Select a resource group for project '{project}':")
                for i, g in enumerate(groups, start=1):
                    print(f"  {i}. {g}")

                idx = input(f"Enter number [1-{len(groups)}] (or press Enter to use default '{project}-rg'): ").strip()
                if idx.isdigit() and 1 <= int(idx) <= len(groups):
                    selected = groups[int(idx) - 1]
                    mc.env.write(key, selected, replace_existing=True)
                    print(f"[AzureResourceGroup] Selected: {selected}")
                    return selected

            except Exception as e:
                print(f"[AzureResourceGroup] CLI discovery failed: {e}")

            # Fallback
            default = f"{project}-rg"
            print(f"[AzureResourceGroup] Using fallback default: {default}")
            mc.env.write(key, default, replace_existing=True)
            return default

    class AzureKeyVault:
        """
        Resolves and verifies Key Vault URI for a project.

        Used by AzureIDs to populate KEY_VAULT_URL.
        """

        @staticmethod
        def get_url(project: str) -> str:
            """
            Returns a Key Vault URI for the given project.

            Tries:
            1. {project}.VAULT_NAME + az show
            2. bm.VaultSetup.ensure_vault_ready(project)

            Args:
                project (str): Project name

            Returns:
                str: Vault URI
            """
            vault_name = mc.env.get(f"{project}.VAULT_NAME", required=False)
            resource_group = bm.AzureIDs.resource_group(project)

            try:
                if vault_name:
                    result = Subprocess.CMD.run([
                        "az", "keyvault", "show",
                        "--name", vault_name,
                        "--resource-group", resource_group,
                        "--query", "properties.vaultUri",
                        "--output", "tsv"
                    ], capture_output=True, text=True, check=True, force_global_shell=True)
                    uri = result.stdout.strip()
                    if uri:
                        print(f"[AzureKeyVault] ✅ Resolved URI for vault '{vault_name}': {uri}")
                        return uri
            except Exception as e:
                print(f"[AzureKeyVault] Could not resolve vault URI via CLI: {e}")

            # Fallback: trigger vault creation
            LOG.info(f"[AzureKeyVault] Triggering vault setup fallback...")
            return bm.VaultSetup.ensure_vault_ready(project)

    class AzureIDs:
        """
        Resolves and validates Azure identity values required for authentication,
        authorization, and resource provisioning.

        Leverages composed classes:
          - AzureTenant
          - AzureSubscription
          - AzureClient
          - AzureAppRegister
          - AzureUser

        Uses project-scoped keys like <project>.AZURE_TENANT_ID
        """
        _cached_user = None

        REQUIRED_KEYS = {
            "AZURE_TENANT_ID": "Tenant ID",
            "AZURE_CLIENT_ID": "Client ID",
            "AZURE_CLIENT_SECRET": "Client Secret",
            "AZURE_SUBSCRIPTION_ID": "Subscription ID",
            "KEY_VAULT_URL": "Key Vault URL",
            "RESOURCE_GROUP": "Azure Resource Group",
            "AZURE_REGION": "Azure Region",
            "DB_NAME": "Database Name"
        }

        @staticmethod
        def get(key: str, project: str, required: bool = True) -> str:
            """
            Resolves a specific identity value from the configured project context.

            Args:
                key (str): Identity key name
                project (str): Project name
                required (bool): Raise error if not found

            Returns:
                str: Resolved identity value
            """
            #Ensure valid user ...
            try:
                user = bm.AzureIDs._cached_user
                if not user:
                    user = bm.AzureUser.get(project)

                if key == "AZURE_TENANT_ID":
                    return bm.AzureTenant.get(project)

                elif key == "AZURE_SUBSCRIPTION_ID":
                    return bm.AzureSubscription.get(project)

                elif key == "AZURE_CLIENT_ID":
                    return bm.AzureClient.get_app(project)["client_id"]

                elif key == "AZURE_CLIENT_SECRET":
                    return bm.AzureClient.setup(project)["client_secret"]

                elif key == "KEY_VAULT_URL":
                    return bm.AzureKeyVault.get_url(project)

                elif key == "RESOURCE_GROUP":
                    return bm.AzureResourceGroup.get(project)

                elif key == "AZURE_REGION":
                    return bm.AzureIDs._resolve_region(project)

                elif key == "DB_NAME":
                    return bm.ProjectUtils.db_name(project)

            except Exception as resolver_error:
                fallback_key = f"{project}.{key}"
                val = mc.env.get(fallback_key, required=False)
                if val:
                    return val
                if required:
                    raise RuntimeError(f"[AzureIDs] ❌ Failed to resolve {key}:\n{resolver_error}")
                return None

        @staticmethod
        def _resolve_region(project: str) -> str:
            """
            Attempts to resolve the Azure region via ENV or from the resource group's metadata.
            """
            env_key = f"{project}.AZURE_REGION"
            region = mc.env.get(env_key, required=False)
            if region:
                return region

            resource_group = bm.AzureIDs.resource_group(project)
            try:
                result = Subprocess.CMD.run(
                    [
                        "az", "group", "show",
                        "--name", resource_group,
                        "--query", "location",
                        "--output", "tsv"
                    ],
                    capture_output=True,
                    text=True,
                    force_global_shell=True
                )
                return result.stdout.strip()
            except Exception as e:
                raise RuntimeError(f"[AzureIDs] ❌ Could not resolve region from resource group '{resource_group}': {e}")

        @staticmethod
        def validate_all(project: str) -> dict:
            """
            Ensures all required identity values are resolvable.

            Args:
                project (str): Project name

            Returns:
                dict: All resolved identity values
            """
            for key in bm.AzureIDs.REQUIRED_KEYS:
                print(f"Attempting to validate {project}.{key}...")
                bm.AzureIDs.get(key, project=project, required=True)

        class AzureIDs:

            @staticmethod
            def tenant_id(project: str) -> str:
                """Get the AZURE_TENANT_ID."""
                tenant_id = mc.env.get("AZURE_TENANT_ID", None)
                if tenant_id is None:
                    tenant_id = bm.AzureIDs.get("AZURE_TENANT_ID", project)
                    mc.env.write("AZURE_TENANT_ID", tenant_id, replace_existing=True)
                return tenant_id

            @staticmethod
            def subscription_id(project: str) -> str:
                """Get the AZURE_SUBSCRIPTION_ID."""
                subscription_id = mc.env.get("AZURE_SUBSCRIPTION_ID", None)
                if subscription_id is None:
                    subscription_id = bm.AzureIDs.get("AZURE_SUBSCRIPTION_ID", project)
                    mc.env.write("AZURE_SUBSCRIPTION_ID", subscription_id, replace_existing=True)
                return subscription_id

            @staticmethod
            def client_id(project: str) -> str:
                """Get the AZURE_CLIENT_ID."""
                client_id = mc.env.get("AZURE_CLIENT_ID", None)
                if client_id is None:
                    client_id = bm.AzureIDs.get("AZURE_CLIENT_ID", project)
                    mc.env.write("AZURE_CLIENT_ID", client_id, replace_existing=True)
                return client_id

            @staticmethod
            def client_secret(project: str) -> str:
                """Get the AZURE_CLIENT_SECRET."""
                client_secret = mc.env.get("AZURE_CLIENT_SECRET", None)
                if client_secret is None:
                    client_secret = bm.AzureIDs.get("AZURE_CLIENT_SECRET", project)
                    mc.env.write("AZURE_CLIENT_SECRET", client_secret, replace_existing=True)
                return client_secret

            @staticmethod
            def key_vault_url(project: str) -> str:
                """Get the KEY_VAULT_URL."""
                key_vault_url = mc.env.get("KEY_VAULT_URL", None)
                if key_vault_url is None:
                    key_vault_url = bm.AzureIDs.get("KEY_VAULT_URL", project)
                    mc.env.write("KEY_VAULT_URL", key_vault_url, replace_existing=True)
                return key_vault_url

            @staticmethod
            def resource_group(project: str) -> str:
                """Get the RESOURCE_GROUP."""
                resource_group = mc.env.get("RESOURCE_GROUP", None)
                if resource_group is None:
                    resource_group = bm.AzureIDs.get("RESOURCE_GROUP", project)
                    mc.env.write("RESOURCE_GROUP", resource_group, replace_existing=True)
                return resource_group

            @staticmethod
            def region(project: str) -> str:
                """Get the AZURE_REGION."""
                region = mc.env.get("AZURE_REGION", None)
                if region is None:
                    region = bm.AzureIDs.get("AZURE_REGION", project)
                    mc.env.write("AZURE_REGION", region, replace_existing=True)
                return region

            @staticmethod
            def db_name(project: str) -> str:
                """Get the DB_NAME."""
                db_name = mc.env.get("DB_NAME", None)
                if db_name is None:
                    db_name = bm.AzureIDs.get("DB_NAME", project)
                    mc.env.write("DB_NAME", db_name, replace_existing=True)
                return db_name

    class VaultSetup:
        """
        Handles creation, validation, and retrieval of Azure Key Vaults for a given project context.

        Resolves dependencies via:
        - AzureIDs (tenant, sub, client, secret, resource group, vault name)
        - Secrets (for post-creation vault session)
        """

        @staticmethod
        def ensure_vault_ready(project: str = None) -> str:
            """
            Main entrypoint. Ensures Key Vault exists and is accessible.

            Returns:
                str: Vault URI
            """
            project = project or mc.env.get("selected_project_name")
            subscription_id = bm.AzureIDs.subscription_id(project)
            region = mc.env.get(f"{project}.AZURE_REGION", required=False) or "eastus"

            bm.VaultSetup.list_existing_vaults(subscription_id, region)

            try:
                vault = bm.VaultSetup.get_vault(project)
                print(f"[VaultSetup] ✅ Vault exists: {vault['name']} ({vault['uri']})")
            except Exception as e:
                print(f"[VaultSetup] ⚠️ Vault not found. Attempting to create it: {e}")
                vault = bm.VaultSetup.create_vault(project)

            uri = vault["uri"]

            if not Secrets.load_vault(project):
                raise RuntimeError("[VaultSetup] ❌ Failed to initialize Secrets client after vault creation.")

            return uri

        @staticmethod
        def list_existing_vaults(subscription_id: str, region: str = None) -> list:
            """
            Lists Key Vaults for the subscription (optionally filtered by region).
            """
            cmd = ["az", "keyvault", "list", "--subscription", subscription_id, "--output", "json"]
            result = Subprocess.CMD.run(cmd, capture_output=True, text=True, force_global_shell=True)
            import json
            vaults = json.loads(result.stdout)

            if region:
                vaults = [v for v in vaults if v.get("location", "").lower() == region.lower()]

            print(f"[VaultSetup] 🔍 Found {len(vaults)} vault(s){f' in region={region}' if region else ''}")
            for v in vaults:
                print(f"  - {v['name']} ({v['location']})")

            return vaults

        @staticmethod
        def ensure_keyvault_provider_registered(subscription_id: str):
            """
            Ensures the Microsoft.KeyVault provider is registered for the subscription.
            """
            result = Subprocess.CMD.run(
                ["az", "provider", "show", "--namespace", "Microsoft.KeyVault", "--query", "registrationState",
                 "--output", "tsv"],
                capture_output=True, text=True, force_global_shell=True
            )
            if result.stdout.strip() != "Registered":
                print("[VaultSetup] 🔧 Registering Microsoft.KeyVault provider...")
                Subprocess.CMD.run(
                    ["az", "provider", "register", "--namespace", "Microsoft.KeyVault"],
                    capture_output=True, text=True, force_global_shell=True
                )
                print("[VaultSetup] ⏳ Waiting for registration...")
                import time
                while True:
                    check = Subprocess.CMD.run(
                        ["az", "provider", "show", "--namespace", "Microsoft.KeyVault", "--query", "registrationState",
                         "--output", "tsv"],
                        capture_output=True, text=True, force_global_shell=True
                    )
                    if check.stdout.strip() == "Registered":
                        break
                    time.sleep(2)
                print("[VaultSetup] ✅ Provider registered.")

        @staticmethod
        def create_vault(project: str) -> dict:
            """
            Creates a new Key Vault.

            Returns:
                dict: { name, uri }
            """
            project = project or mc.env.get("selected_project_name")

            subscription_id = bm.AzureIDs.subscription_id(project)
            bm.VaultSetup.ensure_keyvault_provider_registered(subscription_id)

            vault_name = mc.env.get(f"{project}.VAULT_NAME", required=False) or f"{project.lower()}-vault"
            location = mc.env.get(f"{project}.AZURE_REGION", required=False) or "eastus"
            resource_group = bm.AzureIDs.resource_group(project)

            mc.env.write(f"{project}.VAULT_NAME", vault_name, replace_existing=True)

            print(f"[VaultSetup] 🚀 Creating Key Vault: {vault_name} in {resource_group} ({location})")

            Subprocess.CMD.run([
                "az", "keyvault", "create",
                "--name", vault_name,
                "--location", location,
                "--resource-group", resource_group,
                "--enable-rbac-authorization", "true"
            ], capture_output=True, text=True, force_global_shell=True)

            result = Subprocess.CMD.run([
                "az", "keyvault", "show",
                "--name", vault_name,
                "--resource-group", resource_group,
                "--query", "properties.vaultUri", "--output", "tsv"
            ], capture_output=True, text=True, force_global_shell=True)

            uri = result.stdout.strip()
            print(f"[VaultSetup] ✅ Vault created: {vault_name} ({uri})")

            return {"name": vault_name, "uri": uri}

        @staticmethod
        def get_vault(project: str) -> dict:
            """
            Uses Azure SDK to fetch vault metadata.

            Returns:
                dict: Vault metadata
            """
            from azure.mgmt.keyvault import KeyVaultManagementClient
            from azure.identity import DefaultAzureCredential

            project = project or mc.env.get("selected_project_name")
            subscription_id = bm.AzureIDs.subscription_id(project)
            vault_name = mc.env.get(f"{project}.VAULT_NAME", required=True)
            resource_group = bm.AzureIDs.resource_group(project)

            try:
                client = KeyVaultManagementClient(DefaultAzureCredential(), subscription_id)
                vault = client.vaults.get(resource_group_name=resource_group, vault_name=vault_name)

                return {
                    "name": vault.name,
                    "location": vault.location,
                    "id": vault.id,
                    "uri": vault.properties.vault_uri,
                    "policies": [p.object_id for p in vault.properties.access_policies],
                    "enabled_for_template_deployment": vault.properties.enabled_for_template_deployment,
                }
            except Exception as e:
                raise RuntimeError(f"[VaultSetup] ❌ Failed to retrieve vault '{vault_name}': {e}")

        @staticmethod
        def get_url(project: str) -> str | None:
            """
            Returns Key Vault URI if it exists; returns None if not found.
            Never creates or modifies vault.
            """
            try:
                vault = bm.VaultSetup.get_vault(project)
                return vault["uri"]
            except Exception:
                return None

        @staticmethod
        def get_current_object_id() -> str | None:
            """
            Returns the Object ID of the signed-in user or service principal.
            """
            try:
                # Try Graph-based resolution first
                session = bm.GraphInitialization.get_session("global")
                me = session.get("https://graph.microsoft.com/v1.0/me")
                if me.status_code == 200:
                    return me.json().get("id")
            except Exception:
                pass

            try:
                client_id = bm.AzureIDs.client_id(project=mc.env.get("selected_project_name"))
                result = Subprocess.CMD.run([
                    "az", "ad", "sp", "show", "--id", client_id, "--query", "objectId", "--output", "tsv"
                ], capture_output=True, text=True, check=True, force_global_shell=True)
                return result.stdout.strip()
            except Exception as e:
                raise RuntimeWarning(f"[VaultSetup] Could not resolve objectId: {e}")

    class DatabaseSetup:
        """
        Handles provisioning and connection setup for Azure Database for PostgreSQL.

        Integrates with Azure CLI and environment config to:
        - Check for existing database instances
        - Create a PostgreSQL flexible server
        - Configure firewall, admin login, and network rules
        """

        @staticmethod
        def ensure_postgres_ready(project: str = None) -> dict:
            """
            Main entrypoint. Ensures a PostgreSQL flexible server exists and is reachable.

            Returns:
                dict: { name, fqdn, admin_login }
            """
            project = project or mc.env.get("selected_project_name")
            resource_group = bm.AzureIDs.resource_group(project)
            region = bm.AzureIDs.region(project)
            db_name = bm.AzureIDs.db_name(project)

            existing = bm.DatabaseSetup.get_fqdn(project)
            if existing:
                print(f"[DatabaseSetup] ✅ PostgreSQL already exists: {existing}")
                return existing

            print(f"[DatabaseSetup] ⚠️ Database not found. Attempting to create: {db_name}")
            return bm.DatabaseSetup.create_postgres(project)

        @staticmethod
        def create_postgres(project: str) -> dict:
            """
            Creates a PostgreSQL flexible server with secure defaults.

            Returns:
                dict: { name, fqdn, admin_login }
            """
            resource_group = bm.AzureIDs.resource_group(project)
            region = bm.AzureIDs.region(project)
            db_name = bm.AzureIDs.db_name(project)
            admin_user = "adminuser"
            admin_pass = Passwords.get(f"{db_name}.PASSWORD", project)

            print(f"[DatabaseSetup] 🚀 Creating PostgreSQL server: {db_name}")
            Subprocess.CMD.run([
                "az", "postgres", "flexible-server", "create",
                "--name", db_name,
                "--resource-group", resource_group,
                "--location", region,
                "--admin-user", admin_user,
                "--admin-password", admin_pass,
                "--sku-name", "Standard_B1ms",
                "--storage-size", "32",
                "--yes"
            ], capture_output=True, text=True, force_global_shell=True)

            fqdn = bm.DatabaseSetup.get_fqdn(project)["fqdn"]
            print(f"[DatabaseSetup] ✅ PostgreSQL server created: {fqdn}")

            return {
                "name": db_name,
                "fqdn": fqdn,
                "admin_login": admin_user
            }

        @staticmethod
        def get_fqdn(project: str) -> dict | None:
            """
            Returns FQDN of the existing server if it exists.

            Returns:
                dict: { fqdn } or None
            """
            try:
                db_name = bm.AzureIDs.db_name(project)
                resource_group = bm.AzureIDs.resource_group(project)
                result = Subprocess.CMD.run([
                    "az", "postgres", "flexible-server", "show",
                    "--name", db_name,
                    "--resource-group", resource_group,
                    "--query", "{fqdn: fullyQualifiedDomainName}",
                    "--output", "json"
                ], capture_output=True, text=True, force_global_shell=True)
                return json.loads(result.stdout.strip())
            except Exception:
                return None

    class AzureStrapper:
        """
        Manages Azure authentication and validation for a project, and routes the flow
        to relevant tasks such as Vault or Database setup based on the provided process argument.
        """

        @staticmethod
        def validate_azure_ids(project: str):
            """
            Ensures that all Azure IDs (Tenant ID, Subscription ID, etc.) are valid for the given project.
            If validation fails, the user is prompted to retry or stop.

            Args:
                project (str): The project name for scoping.
            """
            print(f"[AzureStrapper] Validating Azure IDs for project: {project}")

            retries = 0
            max_retries = 3

            while retries < max_retries:
                try:
                    # Attempt to validate all Azure IDs (tenant, subscription, etc.)
                    bm.AzureIDs.validate_all(project)
                    print(f"[AzureStrapper] ✅ Azure IDs validated for project: {project}")
                    return  # Exit the loop if validation succeeds

                except Exception as e:
                    print(f"[AzureStrapper] ❌ Failed to validate Azure IDs: {str(e)}")

                    # If retries are exhausted, raise an error and exit
                    if retries >= max_retries - 1:
                        print(f"[AzureStrapper] ❌ Max retries reached. Aborting.")
                        raise RuntimeError(
                            f"[AzureStrapper] Failed to validate Azure IDs after {max_retries} attempts.")

                    # Prompt the user for retry or quit
                    user_choice = input(f"Would you like to try again? (1 for Yes, 2 for No): ").strip()

                    if user_choice == "1":
                        retries += 1
                        print(f"[AzureStrapper] Retrying... Attempt {retries}/{max_retries}")

                        # Clear the cache using Azure CLI
                        print(f"[AzureStrapper] Clearing Azure CLI cache...")
                        try: Subprocess.CMD.run(["az", "logout"], force_global_shell=True)
                        except Exception: pass
                        time.sleep(2)  # Wait before retrying
                    elif user_choice == "2":
                        print(f"[AzureStrapper] User chose to stop. Aborting.")
                        raise RuntimeError(f"[AzureStrapper] User opted to stop after failure.")
                    else:
                        print("[AzureStrapper] Invalid choice. Please choose 1 to retry or 2 to stop.")
                        continue  # Ask again if the user enters an invalid response

        @staticmethod
        def route_to_process(process: str, project: str):
            """
            Routes the flow to the appropriate setup based on the provided process argument.

            Args:
                process (str): The process to route to ("vault" or "database").
                project (str): The project name for scoping.
            """
            if process == "vault":
                print(f"[AzureStrapper] Routing to Vault setup for project: {project}")
                bm.VaultSetup.ensure_vault_ready(project)
            elif process == "database":
                print(f"[AzureStrapper] Routing to Database setup for project: {project}")
                bm.DatabaseSetup.ensure_postgres_ready(project)
            else:
                raise ValueError(f"[AzureStrapper] ❌ Invalid process: {process}. Use 'vault' or 'database'.")

        @staticmethod
        def setup(project: str, process: str):
            """
            Validates all Azure IDs and routes to the corresponding process for the project.

            Args:
                project (str): The project name for scoping.
                process (str): The process to route to ("vault" or "database").
            """
            print(f"[AzureStrapper] Starting setup for project: {project}")

            # Step 1: Validate all Azure IDs (Tenant ID, Subscription ID, Client ID, etc.)
            bm.AzureStrapper.validate_azure_ids(project)

            # Step 2: Route to the appropriate process (Vault or Database setup)
            bm.AzureStrapper.route_to_process(process, project)

            print(f"[AzureStrapper] ✅ Setup completed for project: {project}")


bm = BackendMethods

import secrets
import string

class Secrets:
    """
    Secure secrets manager for retrieving and caching credentials.
    Primary source: Azure Key Vault.
    Fallback: OS environment variables.

    Does not persist secrets to disk under any circumstances.
    """

    _cache = {}
    _client = None

    @staticmethod
    def sanitize(key: str) -> str:
        sanny_key = Sanitization.purge(key)
        return sanny_key

    @staticmethod
    def load_vault(project: str) -> SecretClient:
        """
        Initialize or retrieve the Azure SecretClient.
        This method is used to interact with Azure Key Vault.

        Returns:
            SecretClient: The Azure SecretClient instance for accessing the vault.
        """
        if Secrets._client:
            return Secrets._client

        url = bm.VaultSetup.get_url(project)
        if not url:
            raise RuntimeError(f"[Secrets] Vault URL not found for project: {project}")

        print("[Secrets] Vault URL found... Now ensuring permissions to modify...")
        bm.AzureClient.get_service_principal(bm.AzureIDs.client_id(project))

        try:
            # Using DefaultAzureCredential to authenticate
            client = SecretClient(vault_url=url, credential=DefaultAzureCredential())
            Secrets._client = client
            print("[Secrets] Vault successfully initialized!")
            return client
        except Exception as e:
            raise RuntimeError(f"[Secrets] Failed to initialize SecretClient: {e}")



    @staticmethod
    def store(name: str, value: str, project: str) -> None:
        """
        Persist the secret to Azure Key Vault.
        This method will overwrite any existing secret in Key Vault.

        Args:
            name (str): The name of the secret.
            value (str): The secret value.
            project (str): The project name.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        try:
            client = Secrets.load_vault(project)
            # Persist the secret
            secret = client.set_secret(secret_key, value)
            print(f"[Secrets] Successfully stored secret '{secret_key}' in Key Vault.")
            Secrets._cache[secret_key] = value  # Cache the value for local use
        except Exception as e:
            raise RuntimeError(f"[Secrets] Failed to store secret in Key Vault: {e}")

    @staticmethod
    def set(name: str, value: str, project: str, persist: bool = False) -> None:
        """
        Set the secret in cache and optionally persist it to Azure Key Vault.

        Args:
            name (str): The name of the secret.
            value (str): The secret value.
            project (str): The project name.
            persist (bool): Whether to persist the secret to Azure Key Vault. Default is False.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        # Store in local cache
        Secrets._cache[secret_key] = value
        print(f"[Secrets] Stored secret '{secret_key}' in cache.")

        # Optionally store the secret in Azure Key Vault
        if persist:
            Secrets.store(name, value, project)

    @staticmethod
    def has(name: str, project: str) -> bool:
        """
        Check if the secret exists in the cache or in Azure Key Vault.

        Args:
            name (str): The name of the secret.
            project (str): The project name.

        Returns:
            bool: True if the secret exists, False otherwise.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        if secret_key in Secrets._cache:
            return True

        try:
            client = Secrets.load_vault(project)
            client.get_secret(secret_key)  # Will raise if not found
            return True
        except Exception:
            return False

    @staticmethod
    def get(name: str, project: str, required: bool = True, store: bool = True) -> str | None:
        """
        Retrieve the secret from the cache or Azure Key Vault.

        Args:
            name (str): The name of the secret.
            project (str): The project name.
            required (bool): Whether the secret is required.
            store (bool): Whether to store the secret in the cache if found.

        Returns:
            str: The secret value.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        def return_secret(val):
            if store:
                Secrets._cache[secret_key] = val
            return val

        # Check cache first
        if secret_key in Secrets._cache:
            return return_secret(Secrets._cache[secret_key])

        # Check Key Vault
        try:
            client = Secrets.load_vault(project)
            val = client.get_secret(secret_key).value
            return return_secret(val)
        except Exception:
            pass

        if required:
            raise RuntimeError(f"[Secrets] Could not find secret: {secret_key}")
        return None

    @staticmethod
    def get_list(project: str) -> list[str]:
        """
        List all secrets in the Key Vault for a specific project.

        Args:
            project (str): The project name.

        Returns:
            list[str]: List of secret names.
        """
        client = Secrets.load_vault(project)
        prefix = f"{project}."
        results = []
        for prop in client.list_properties_of_secrets():
            if prop.name.startswith(prefix):
                try:
                    val = Secrets.get(prop.name[len(prefix):], project=project, required=False)
                    if val:
                        results.append(prop.name)
                except Exception:
                    continue
        return results

    @staticmethod
    def make_list(project: str) -> dict[str, str]:
        """
        Get all cached secrets for a specific project.

        Args:
            project (str): The project name.

        Returns:
            dict[str, str]: A dictionary of secret names and values.
        """
        prefix = f"{project}."
        return {
            key[len(prefix):]: val
            for key, val in Secrets._cache.items()
            if key.startswith(prefix)
        }

    @staticmethod
    def preload_cache(secrets: dict[str, str], project: str) -> None:
        """
        Preload multiple secrets into the cache.

        Args:
            secrets (dict): A dictionary of secret names and values.
            project (str): The project name.
        """
        if not isinstance(secrets, dict):
            raise TypeError("Expected a dictionary of secrets.")
        for k, v in secrets.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError(f"Secret keys/values must be strings. Got {k}={v}")
            Secrets._cache[f"{project}.{k}"] = v

    @staticmethod
    def clear_cache() -> None:
        """
        Clear the secret cache.
        """
        Secrets._cache.clear()
        Secrets._client = None

class Passwords:
    """
    A utility class for generating secure passwords with configurable options.
    """

    @staticmethod
    def generate_password(
            length: int = 16,
            min_length: int = 8,
            use_uppercase: bool = True,
            use_lowercase: bool = True,
            use_digits: bool = True,
            use_special_chars: bool = True
    ) -> str:
        """
        Generates a secure password that meets the specified complexity requirements.

        Args:
            length (int): Length of the password. Default is 16.
            min_length (int): Minimum length of the password. Default is 8.
            use_uppercase (bool): Whether to include uppercase letters. Default is True.
            use_lowercase (bool): Whether to include lowercase letters. Default is True.
            use_digits (bool): Whether to include digits. Default is True.
            use_special_chars (bool): Whether to include special characters. Default is True.

        Returns:
            str: The generated password.
        """
        print("[Passwords] Generating password now!")
        if length < min_length:
            raise ValueError(f"Password length should be at least {min_length} characters.")

        alphabet = ""
        if use_uppercase:
            alphabet += string.ascii_uppercase
        if use_lowercase:
            alphabet += string.ascii_lowercase
        if use_digits:
            alphabet += string.digits
        if use_special_chars:
            alphabet += string.punctuation

        if not alphabet:
            raise ValueError("At least one character type must be selected.")

        password = ''.join(secrets.choice(alphabet) for i in range(length))

        return password

    @staticmethod
    def generate_simple_password(length: int = 12) -> str:
        """
        Generates a simple password with default settings:
        - Length: 12 characters
        - Includes lowercase, uppercase, digits, and special characters.

        Args:
            length (int): Length of the password. Default is 12.

        Returns:
            str: The generated simple password.
        """
        return Passwords.generate_password(length=length)

    @staticmethod
    def validate_password(password: str) -> bool:
        """
        Validates the password complexity by checking its length and character types.

        Args:
            password (str): The password to validate.

        Returns:
            bool: True if the password meets the criteria, False otherwise.
        """
        if len(password) < 8:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.islower() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        if not any(c in string.punctuation for c in password):
            return False
        return True

    @staticmethod
    def get(name: str, project: str, length: int = 16) -> str:
        """
        Retrieves the password from the environment if it exists,
        otherwise generates and stores a new password for future use.

        Args:
            name: The password key for identifying it.
            project (str): The project name to associate the password with.
            length (int): Length of the password. Default is 16.

        Returns:
            str: The password (either retrieved from env or newly generated).
        """
        # Try to get the password from the environment
        print(f"[Passwords] Attempting to get password for {name} ...")
        password = Secrets.get(name, project, required=False, store=True)
        print(password)
        valid_password = None

        # If the password is not found, generate and store a new one
        if not password:
            print(f"[Passwords] No password found! Generating ...")
            password = Passwords.generate_password(length)
            Secrets.set(name, password, project, persist=True)

        if password:
            print(f"[Password] Password found.")
            valid_password = Passwords.validate_password(password)
            if valid_password is False: valid_password = Passwords.generate_password(length)

        print(f"[Passwords] Password successfully initialized!")

        return valid_password


