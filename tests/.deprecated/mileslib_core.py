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
from milesazure.identity import DefaultAzureCredential
from milesazure.mgmt.resource import ResourceManagementClient
from milesazure.mgmt.keyvault import KeyVaultManagementClient
from milesazure.core.exceptions import ResourceExistsError
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
from milesazure.identity import DefaultAzureCredential
from milesazure.keyvault.secrets import SecretClient
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

