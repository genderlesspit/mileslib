# tenant.py

import time
from pathlib import Path
from typing import Optional

from backend_methods.milesrequests import Requests
from context import milescontext as mc  # mc.cache is the Cache instance
from milesazure.run import run_az


class AzureTenant:
    """
    Manages Azure Tenant ID initialization, validation, and retrieval.

    Uses project-scoped key: <project>.AZURE_TENANT_ID
    """

    @staticmethod
    def init(project: str) -> str:
        print(f"[AzureTenant] No tenant ID found for project: {project}")
        AzureTenant.help()
        time.sleep(1)

        tenant_id = input("Enter your Azure Tenant ID: ").strip()

        if not tenant_id:
            print("[AzureTenant] ❌ Input was empty")
            raise ValueError("Input cannot be empty")

        try:
            AzureTenant.validate(tenant_id)
        except Exception as ex:
            print(f"[AzureTenant] ❌ Validation error: {ex}")
            raise RuntimeError(f"Validation failed: {ex}")

        mc.cache.set(project, "AZURE_TENANT_ID", tenant_id, include_in_cfg=project)
        print(f"[AzureTenant] ✅ Returning tenant ID: {tenant_id!r}")
        return tenant_id

    @staticmethod
    def get(project: str) -> str:
        """
        Retrieves the tenant ID for a project, prompting if missing.

        Args:
            project (str): Project scope for env key.

        Returns:
            str: Validated tenant ID.
        """
        tenant_id = mc.cache.get(
            project,
            "AZURE_TENANT_ID",
            recall=lambda: AzureTenant.init(project)
        )

        if tenant_id is None:
            # Should not happen: recall would return a string or raise
            raise RuntimeError(f"[AzureTenant] Could not obtain tenant ID for '{project}'")

        AzureTenant.validate(tenant_id)
        return tenant_id

    @staticmethod
    def validate(tenant_id: str) -> bool:
        """
        Validates the given tenant ID by checking OpenID metadata.

        Args:
            tenant_id (str): The Azure AD tenant ID to validate.

        Returns:
            bool: True if valid; raises RuntimeError otherwise.
        """
        url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
        resp = Requests.http_get(url, expect_json=True)
        if not isinstance(resp, dict) or tenant_id not in resp.get("issuer", ""):
            raise RuntimeError(f"[AzureTenant] Invalid tenant_id: {tenant_id}")
        return True

    @staticmethod
    def help():
        """
        Prints human instructions for locating your Azure Tenant ID.
        """
        print("[🔧 How to Find Your Azure Tenant ID]")
        print("─────────────────────────────────────")
        print("📍 Azure Portal (recommended):")
        print("  1. Go to: https://portal.azure.com/")
        print("  2. Select 'Azure Active Directory' from the sidebar.")
        print("  3. Your Tenant ID is listed on the Overview page.")
        print("🧠 Tip: It looks like a UUID (e.g. 72f988bf-86f1-41af-91ab-2d7cd011db47).")
        print("─────────────────────────────────────")


class AzureSubscription:
    """
    Handles Azure Subscription ID selection, validation, and caching.

    Uses project-scoped key: <project>.AZURE_SUBSCRIPTION_ID
    """

    @staticmethod
    def init(project: str) -> str:
        """
        Prompts the user to choose a subscription if multiple exist,
        then stores and validates the selected subscription ID.

        Args:
            project (str): Project scope.

        Returns:
            str: Validated subscription ID.
        """
        print(f"[AzureSubscription] Fetching available subscriptions...")
        subs = AzureSubscription._get_all()

        if not subs:
            raise RuntimeError("[AzureSubscription] No subscriptions found. Are you logged in to Azure?")

        if len(subs) == 1:
            sub = subs[0]
            print(f"[AzureSubscription] One subscription found: {sub['name']} ({sub['id']})")
        else:
            print("\n🔢 Choose a subscription:")
            for i, s in enumerate(subs, 1):
                print(f" {i}. {s['name']} ({s['id']})")
            print()

            while True:
                try:
                    idx = int(input(f"Enter number (1–{len(subs)}): ").strip()) - 1
                    if 0 <= idx < len(subs):
                        sub = subs[idx]
                        break
                except Exception:
                    pass
                print("❌ Invalid input. Try again.")

        sub_id = sub["id"]
        # Persist into cache + .env under "<project>.AZURE_SUBSCRIPTION_ID"
        mc.cache.set(project, "AZURE_SUBSCRIPTION_ID", sub_id, include_in_cfg=project)

        print(f"[AzureSubscription] Subscription set for '{project}': {sub['name']} ({sub_id})")
        return sub_id

    @staticmethod
    def get(project: str) -> str:
        """
        Retrieves the project’s subscription ID or triggers selection.

        Args:
            project (str): Project name.

        Returns:
            str: Subscription ID.
        """
        sub_id = mc.cache.get(
            project,
            "AZURE_SUBSCRIPTION_ID",
            recall=lambda: AzureSubscription.init(project)
        )

        if sub_id is None:
            raise RuntimeError(f"[AzureSubscription] Could not obtain subscription ID for '{project}'")

        AzureSubscription.validate(sub_id)
        return sub_id

    @staticmethod
    def validate(sub_id: str) -> bool:
        """
        Verifies the subscription ID exists in the current Azure context.

        Args:
            sub_id (str): Azure subscription ID

        Returns:
            bool: True if valid; raises ValueError otherwise.
        """
        subs = AzureSubscription._get_all()
        valid_ids = [s["id"] for s in subs]
        if sub_id not in valid_ids:
            raise ValueError(f"[AzureSubscription] Subscription ID not recognized: {sub_id}")
        return True

    @staticmethod
    def _get_all() -> list[dict]:
        """
        Returns a list of all available Azure subscriptions.

        Returns:
            list of dicts with keys 'id' and 'name'
        """
        raw = run_az(
            ["az", "account", "list", "--output", "json"],
            capture_output=True
        )
        # Assume run_az already parsed JSON into Python list[dict]
        return raw

    @staticmethod
    def help():
        """
        Prints CLI guidance on managing Azure subscriptions.
        """
        print("\n[🔧 Azure Subscription Help]")
        print("────────────────────────────")
        print("1. Sign in with: `az login`")
        print("2. See subscriptions: `az account list --output table`")
        print("3. Set a default: `az account set --subscription <id>`")
        print("────────────────────────────\n")

class AzureResourceGroup:
    """
    Manages the Azure Resource Group for a given project.
    Caches the resource group name under: <project>.AZURE_RESOURCE_GROUP
    """

    @staticmethod
    def get(project: str) -> str:
        """
        Fetch the resource group for a project from cache or initialize interactively.
        """
        return mc.cache.get(
            project,
            "AZURE_RESOURCE_GROUP",
            recall=lambda: AzureResourceGroup.init(project)
        )

    @staticmethod
    def init(project: str) -> str:
        """
        Prompt the user for the Azure Resource Group name and ensure it exists.
        Creates it interactively if not found.
        """
        print(f"[AzureResourceGroup] Enter the Azure Resource Group name for project: {project}")
        rg = input("Resource Group: ").strip()

        if not AzureResourceGroup.exists(rg):
            print(f"[AzureResourceGroup] ❌ Resource group '{rg}' does not exist.")
            choice = input("Would you like to create it? (y/N): ").strip().lower()
            if choice == "y":
                location = input("Enter Azure region (default: eastus): ").strip() or "eastus"
                AzureResourceGroup.create(rg, location)
            else:
                raise RuntimeError(f"[AzureResourceGroup] Aborted: Resource group '{rg}' does not exist.")

        AzureResourceGroup.validate(rg)
        mc.cache.set(project, "AZURE_RESOURCE_GROUP", rg, include_in_cfg=project)
        return rg

    @staticmethod
    def exists(rg_name: str) -> bool:
        """
        Check if the given resource group exists.
        """
        result = run_az(["az", "group", "exists", "--name", rg_name], capture_output=True)
        return result is True or result == "true"

    @staticmethod
    def create(rg_name: str, location: str) -> None:
        """
        Create the resource group if it doesn't exist.
        """
        print(f"[AzureResourceGroup] 🛠️ Creating resource group '{rg_name}' in region '{location}'...")
        run_az([
            "az", "group", "create",
            "--name", rg_name,
            "--location", location
        ], capture_output=True)

    @staticmethod
    def validate(rg_name: str) -> bool:
        """
        Validate that the specified resource group exists, else raise error.
        """
        if not AzureResourceGroup.exists(rg_name):
            raise RuntimeError(f"[AzureResourceGroup] ❌ Resource group does not exist: {rg_name}")
        return True

class AzureRegion:
    """
    Resolves the region (location) of the project's resource group.
    Uses project-scoped key: <project>.AZURE_REGION
    """

    @staticmethod
    def get(project: str) -> str:
        return mc.cache.get(
            project,
            "AZURE_REGION",
            recall=lambda: AzureRegion.init(project)
        )

    @staticmethod
    def init(project: str) -> str:
        rg = AzureResourceGroup.get(project)

        try:
            data = run_az(["az", "group", "show", "--name", rg], capture_output=True)
            region = data.get("location", "").strip()
        except Exception as ex:
            raise RuntimeError(f"[AzureRegion] Could not resolve region from resource group '{rg}': {ex}")

        if not region:
            raise RuntimeError(f"[AzureRegion] Region missing from az group show response: {data}")

        mc.cache.set(project, "AZURE_REGION", region, include_in_cfg=project)
        print(f"[AzureRegion] Region resolved from '{rg}': {region}")
        return region

class AzureUser:
    """
    Handles interactive login to Azure CLI, caches the result, and validates
    the authenticated account against project-scoped tenant and subscription.

    Ensures:
      - Clean login (once per session)
      - Valid tenant ID and subscription ID
    """

    _cached_user: Optional[dict] = None

    @staticmethod
    def get(project: str) -> dict:
        """
        Returns the current user context, logging in if not already cached.

        Args:
            project (str): Project name

        Returns:
            dict: Validated CLI user context
        """
        if AzureUser._cached_user:
            return AzureUser._cached_user

        try:
            print("[AzureUser] Attempting to reuse existing Azure CLI session...")
            context = AzureUser._validate_context(project)
        except Exception as e:
            print(f"[AzureUser] Existing session invalid or missing. Reason: {e}")
            context = AzureUser.login(project)

        AzureUser._cached_user = context
        print(f"[AzureUser] User context successfully retrieved!: {context}")
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
        tenant_id = AzureTenant.get(project)

        # Add the tenant ID to the az login command
        run_az(
            ["az", "login", "--tenant", tenant_id],
            capture_output=False
        )

        context = AzureUser._validate_context(project)
        AzureUser._cached_user = context
        return context

    @staticmethod
    def _validate_context(project: str) -> dict:
        """
        Validates current Azure CLI user context against expected tenant and subscription.

        Args:
            project (str): Project scope

        Returns:
            dict: Validated Azure identity context
        """
        expected_tenant = AzureTenant.get(project)
        expected_sub = AzureSubscription.get(project)

        cli_context = run_az(
            ["az", "account", "show", "--output", "json"],
            capture_output=True
        )

        actual_tenant = cli_context.get("tenantId")
        actual_sub = cli_context.get("id")
        user_info = cli_context.get("user", {})
        display_name = user_info.get("name", "Unknown")
        user_type = user_info.get("type", "Unknown")


        # 🧠 Inject this check:
        if user_type.lower() != "user":
            raise RuntimeError(
                f"[AzureUser] ❌ Expected a user identity but got '{user_type}'. Please run `az logout`."
            )

        if actual_tenant != expected_tenant:
            raise RuntimeError(
                f"[AzureUser] ❌ Tenant mismatch: CLI={actual_tenant} vs Config={expected_tenant}"
            )
        if actual_sub != expected_sub:
            raise RuntimeError(
                f"[AzureUser] ❌ Subscription mismatch: CLI={actual_sub} vs Config={expected_sub}"
            )

        display_name = user_info.get("name", "Unknown")
        print(f"[AzureUser] ✅ Logged in as: {display_name} ({user_type})")

        resource_group = AzureResourceGroup.get(project)
        region = AzureRegion.get(project)

        return {
            "tenant_id": actual_tenant,
            "subscription_id": actual_sub,
            "user": user_info,
            "raw": cli_context,
            "resource_group": resource_group,
            "region": region
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


# Convenience aliases
user = AzureUser.get
tenant_id = AzureTenant.get
subscription_id = AzureSubscription.get
