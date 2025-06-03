# tenant.py
import logging
import time
from pathlib import Path
from typing import Optional, List, Dict, Any

from backend_methods.milesrequests import Requests
from context import milescontext as mc  # mc.cache is the Cache instance
from milesazure.run import run_az

logger = logging.getLogger(__name__)

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
    Manages Azure Subscription ID for a project:
      - Lists subscriptions in the current tenant
      - Prompts once if needed, then caches under "<project>.AZURE_SUBSCRIPTION_ID"
      - Ensures all future CLI calls use `az account set --subscription <id>`, with a wait loop to confirm the switch
    """

    @staticmethod
    def _list_for_tenant(tenant_id: str) -> List[Dict[str, Any]]:
        """
        Return all subscriptions in the given tenant via:
          az account list --all --query "[?tenantId=='<tenant_id>']" --output json
        """
        cmd = [
            "az", "account", "list", "--all",
            "--query", f"[?tenantId=='{tenant_id}']",
            "--output", "json"
        ]
        subs = run_az(cmd, capture_output=True)
        if not isinstance(subs, list):
            raise RuntimeError(f"[AzureSubscription._list_for_tenant] Expected JSON array, got: {subs!r}")
        return subs

    @staticmethod
    def _pick_subscription(subs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        If exactly one entry, return it. Otherwise, prompt user to pick from a numbered list.
        """
        if len(subs) == 1:
            return subs[0]

        print("Available subscriptions:")
        for i, s in enumerate(subs, 1):
            name = s.get("name", "<unnamed>")
            sid = s.get("id", "<no-id>")
            print(f"  {i}. {name} ({sid})")

        while True:
            choice = input(f"Select subscription [1–{len(subs)}]: ").strip()
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(subs):
                    return subs[idx]
            except ValueError:
                pass
            print("Invalid selection, try again.")

    @staticmethod
    def _warn_no_subscriptions(target_tenant: str, default_tenant: Optional[str] = None) -> None:
        """
        Warn that `target_tenant` has no subscriptions, and suggest next steps succinctly.
        """
        lines = [
            f"No subscriptions found in tenant: {target_tenant}",
            f"You are logged into Azure CLI under '{target_tenant}'.",
            "Either switch to a tenant with a subscription or request one here:",
            "  https://portal.azure.com/#view/Microsoft_Azure_Billing/SubscriptionsBlade"
        ]
        if default_tenant:
            lines.insert(2, f"Your default tenant ({default_tenant}) may have a subscription.")
        logger.warning(" | ".join(lines))

    @staticmethod
    def _wait_for_set(sub_id: str, timeout_seconds: int = 30, poll_interval: int = 3) -> None:
        """
        Wait until `az account show --query id` returns sub_id, or timeout.
        Raises a RuntimeError if timeout is reached or if run_az errors.
        """
        elapsed = 0

        def _current_sub_id() -> str:
            try:
                info = run_az(["az", "account", "show", "--query", "id", "--output", "tsv"], capture_output=True)
                if not isinstance(info, str):
                    raise RuntimeError(f"[AzureSubscription._wait_for_set] Unexpected type for account id: {info!r}")
                return info.strip()
            except Exception as ex:
                raise RuntimeError(f"[AzureSubscription._wait_for_set] Error fetching current subscription: {ex}")

        while True:
            current_id = _current_sub_id()
            if current_id.lower() == sub_id.lower():
                logger.info(f"[AzureSubscription] Subscription switch confirmed: {sub_id}")
                return

            if elapsed >= timeout_seconds:
                raise RuntimeError(f"[AzureSubscription._wait_for_set] Timed out waiting for subscription to switch to '{sub_id}'. "
                                   f"Last seen '{current_id}'.")
            logger.debug(f"[AzureSubscription] Waiting for subscription switch (elapsed={elapsed}s). "
                         f"Desired='{sub_id}', current='{current_id}'.")
            time.sleep(poll_interval)
            elapsed += poll_interval

    @staticmethod
    def init(project: str) -> str:
        """
        List subscriptions in the current tenant. If none exist, warn and error.
        If one exists, select it automatically. Otherwise, prompt the user.
        Cache under "<project>.AZURE_SUBSCRIPTION_ID" and run `az account set`,
        then wait until the switch is confirmed.
        """
        tenant_id = AzureTenant.get(project)
        subs = AzureSubscription._list_for_tenant(tenant_id)

        if not subs:
            # Attempt to detect a default tenant for quicker guidance
            default_tenant: Optional[str] = None
            try:
                info = run_az(["az", "account", "show"], capture_output=True)
                default_tenant = info.get("tenantId") if isinstance(info, dict) else None
            except Exception:
                default_tenant = None

            AzureSubscription._warn_no_subscriptions(tenant_id, default_tenant)
            raise RuntimeError(f"[AzureSubscription.init] No subscriptions in tenant {tenant_id}.")

        chosen = AzureSubscription._pick_subscription(subs)
        sub_id = chosen.get("id", "")
        if not sub_id:
            raise RuntimeError(f"[AzureSubscription.init] Malformed subscription entry: {chosen!r}")

        # Persist this subscription in CLI context
        try:
            run_az(["az", "account", "set", "--subscription", sub_id], capture_output=True)
        except Exception as ex:
            raise RuntimeError(f"[AzureSubscription.init] Could not set subscription '{sub_id}': {ex}")

        logger.info(f"[AzureSubscription.init] Initiated subscription switch to: {sub_id}")
        AzureSubscription._wait_for_set(sub_id)

        mc.cache.set(project, "AZURE_SUBSCRIPTION_ID", sub_id, include_in_cfg=project)
        logger.info(f"[AzureSubscription.init] Cached subscription for project '{project}': {sub_id}")
        return sub_id

    @staticmethod
    def get(project: str) -> str:
        """
        Return cached subscription ID or trigger init(). Then verify it still exists in the tenant.
        Finally, re-run `az account set` and wait for confirmation if needed.
        """
        sub_id = mc.cache.get(
            project,
            "AZURE_SUBSCRIPTION_ID",
            recall=lambda: AzureSubscription.init(project)
        )
        if not sub_id:
            raise RuntimeError(f"[AzureSubscription.get] No subscription ID for '{project}'")

        # Validate presence
        tenant_id = AzureTenant.get(project)
        subs = AzureSubscription._list_for_tenant(tenant_id)
        valid_ids = {s.get("id", "") for s in subs if isinstance(s.get("id"), str)}
        if sub_id not in valid_ids:
            raise ValueError(f"[AzureSubscription.get] Subscription '{sub_id}' not in tenant {tenant_id}")

        # Re-apply subscription set and confirm
        try:
            run_az(["az", "account", "set", "--subscription", sub_id], capture_output=True)
        except Exception as ex:
            raise RuntimeError(f"[AzureSubscription.get] Could not re-set subscription '{sub_id}': {ex}")

        logger.info(f"[AzureSubscription.get] Re-initiated subscription switch to: {sub_id}")
        AzureSubscription._wait_for_set(sub_id)

        logger.info(f"[AzureSubscription.get] Subscription '{sub_id}' is active and verified.")
        return sub_id

    @staticmethod
    def help() -> None:
        """
        Print concise guidance for common subscription commands.
        """
        help_lines = [
            "Azure Subscription Help:",
            " 1) az login --tenant <tenant-id>",
            " 2) az account list --all --query \"[?tenantId=='<tenant-id>']\" --output table",
            " 3) az account set --subscription <subscription-id>"
        ]
        print("\n".join(help_lines))

class AzureResourceGroup:
    """
    Ensures a resource group named "<project>-rg" exists under the project's Azure subscription.
    Caches under "<project>.AZURE_RESOURCE_GROUP".
    """

    @staticmethod
    def _exists(rg_name: str) -> bool:
        """
        Return True if "az group exists --name <rg_name>" yields true.
        """
        try:
            exists = run_az(["az", "group", "exists", "--name", rg_name], capture_output=True)
        except Exception as ex:
            raise RuntimeError(f"[AzureResourceGroup._exists] Error checking '{rg_name}': {ex}")
        return bool(exists) if isinstance(exists, bool) else False

    @staticmethod
    def _create(rg_name: str, location: str) -> None:
        """
        Create the resource group via:
          az group create --name <rg_name> --location <location> --output json

        Then wait until the RG is fully provisioned (polling _exists).
        Raises a RuntimeError if creation fails or times out.
        """
        # Defined variables
        timeout_seconds = 60
        poll_interval = 5
        elapsed = 0

        # Sub-function: checks existence and logs status
        def _wait_for_creation() -> None:
            nonlocal elapsed
            while True:
                try:
                    if AzureResourceGroup._exists(rg_name):
                        logger.info(f"[AzureResourceGroup] Resource group '{rg_name}' is now available.")
                        return
                except RuntimeError as ex:
                    raise RuntimeError(f"[AzureResourceGroup._create] Error while waiting for '{rg_name}': {ex}")

                if elapsed >= timeout_seconds:
                    raise RuntimeError(f"[AzureResourceGroup._create] Timed out waiting for '{rg_name}' to be provisioned.")
                logger.debug(f"[AzureResourceGroup] Waiting for '{rg_name}' to be provisioned (elapsed={elapsed}s)...")
                time.sleep(poll_interval)
                elapsed += poll_interval

        # Logic: attempt creation, then wait
        try:
            run_az(
                ["az", "group", "create", "--name", rg_name, "--location", location],
                capture_output=True
            )
        except Exception as ex:
            raise RuntimeError(f"[AzureResourceGroup._create] Could not create '{rg_name}': {ex}")

        logger.info(f"[AzureResourceGroup] Created resource group '{rg_name}'. Beginning wait loop...")
        _wait_for_creation()
        print(f"[AzureResourceGroup] Resource group '{rg_name}' successfully created and ready!")

    @staticmethod
    def init(project: str, location: str = "eastus") -> str:
        """
        Compute rg_name = "<project>-rg". Ensure Azure CLI is set to the project subscription.
        If the group doesn't exist, create it. Cache and return the name.
        """
        # 1) Set CLI to the correct subscription
        AzureSubscription.get(project)

        # 2) Determine RG name
        rg_name = f"{project}-rg"

        # 3) Check or create
        if not AzureResourceGroup._exists(rg_name):
            AzureResourceGroup._create(rg_name, location)

        if not AzureResourceGroup._exists(rg_name):
            raise RuntimeError(f"[AzureResourceGroup.init] '{rg_name}' still missing after create attempt.")

        mc.cache.set(project, "AZURE_RESOURCE_GROUP", rg_name, include_in_cfg=project)
        logger.info(f"[AzureResourceGroup.init] Cached resource group: {rg_name}")
        return rg_name

    @staticmethod
    def get(project: str) -> str:
        """
        Return "<project>-rg" from cache or call init(). Re-create if it was deleted externally.
        """
        rg_name = mc.cache.get(
            project,
            "AZURE_RESOURCE_GROUP",
            recall=lambda: AzureResourceGroup.init(project)
        )
        if not rg_name:
            raise RuntimeError(f"[AzureResourceGroup.get] No RG for '{project}'")

        if not AzureResourceGroup._exists(rg_name):
            return AzureResourceGroup.init(project)

        return rg_name

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
      - Waits until CLI actually reflects tenant/subscription switches
    """

    _cached_user: Optional[Dict[str, Any]] = None

    @staticmethod
    def _current_cli_tenant() -> str:
        """
        Returns the tenantId that 'az account show' is currently using,
        or raises if it can’t parse a valid string back.
        """
        info = run_az(
            ["az", "account", "show", "--query", "tenantId", "--output", "tsv"],
            capture_output=True
        )
        if not isinstance(info, str):
            raise RuntimeError(f"[AzureUser] Unexpected 'az account show' output for tenant: {info!r}")
        return info.strip()

    @staticmethod
    def _wait_for_tenant(expected_tenant: str, timeout: int = 30, poll_interval: int = 3) -> None:
        """
        Polls 'az account show' until the CLI’s tenantId equals expected_tenant.
        Raises after timeout seconds if still mismatched.
        """
        elapsed = 0
        while True:
            current = AzureUser._current_cli_tenant()
            if current.lower() == expected_tenant.lower():
                logger.info(f"[AzureUser] Tenant switch confirmed: {expected_tenant}")
                return

            if elapsed >= timeout:
                raise RuntimeError(
                    f"[AzureUser] Timed out waiting for CLI tenant to switch to '{expected_tenant}'. "
                    f"Last seen '{current}'."
                )

            logger.debug(
                f"[AzureUser] Waiting for tenant switch (elapsed={elapsed}s). "
                f"Desired='{expected_tenant}', current='{current}'"
            )
            time.sleep(poll_interval)
            elapsed += poll_interval

    @staticmethod
    def get(project: str) -> Dict[str, Any]:
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
            context = AzureUser._validate_and_fix_context(project)
        except Exception as e:
            print(f"[AzureUser] Existing session invalid or missing. Reason: {e}")
            context = AzureUser.login(project)

        AzureUser._cached_user = context
        print(f"[AzureUser] User context successfully retrieved!: {context}")
        return context

    @staticmethod
    def login(project: str) -> Dict[str, Any]:
        """
        Clears token cache, prompts interactive login, and validates context.

        Args:
            project (str): Project name

        Returns:
            dict: Validated user metadata
        """
        print("[AzureUser] 🔐 Logging in via Azure CLI...")
        tenant_id = AzureTenant.get(project)

        # Interactive login with forced tenant
        run_az(
            ["az", "login", "--tenant", tenant_id],
            capture_output=False
        )

        # Wait until CLI actually flips to expected tenant
        AzureUser._wait_for_tenant(tenant_id)

        # Ensure subscription is set (AzureSubscription.get sets and waits internally)
        AzureSubscription.get(project)

        # Now fetch the full context
        cli_context = run_az(
            ["az", "account", "show", "--output", "json"],
            capture_output=True
        )

        # Validate everything one more time
        return AzureUser._build_context(project, cli_context)

    @staticmethod
    def _validate_and_fix_context(project: str) -> Dict[str, Any]:
        """
        Validates current Azure CLI user context against expected tenant and subscription.
        If there is a mismatch, attempts to fix by re-logging in or resetting subscription,
        waiting for the CLI to reflect changes, and then re-validating.

        Args:
            project (str): Project scope

        Returns:
            dict: Validated Azure identity context
        """
        expected_tenant = AzureTenant.get(project)
        expected_sub = mc.cache.get(
            project,
            "AZURE_SUBSCRIPTION_ID",
            recall=lambda: AzureSubscription.init(project)
        )
        if not expected_sub:
            raise RuntimeError(f"[AzureUser] No AZURE_SUBSCRIPTION_ID cached for '{project}'")

        # 1. Check current tenant
        try:
            actual_tenant = AzureUser._current_cli_tenant()
        except Exception as ex:
            raise RuntimeError(f"[AzureUser] Could not query CLI tenant: {ex}")

        if actual_tenant.lower() != expected_tenant.lower():
            logger.warning(
                f"[AzureUser] Tenant mismatch detected (CLI='{actual_tenant}' vs Config='{expected_tenant}'). "
                "Attempting to re-login."
            )
            # Force re-login to the expected tenant
            run_az(["az", "login", "--tenant", expected_tenant], capture_output=False)
            AzureUser._wait_for_tenant(expected_tenant)

        # 2. Ensure subscription is set correctly (this will set + wait)
        AzureSubscription.get(project)

        # 3. Fetch fresh CLI context
        cli_context = run_az(
            ["az", "account", "show", "--output", "json"],
            capture_output=True
        )

        # 4. Build and return validated context or raise if still mismatched
        return AzureUser._build_context(project, cli_context)

    @staticmethod
    def _build_context(project: str, cli_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        After CLI has the right tenant & subscription, check again and return context.
        Raises if final validation fails.

        Args:
            project (str): Project scope
            cli_context (dict): Raw JSON from `az account show`

        Returns:
            dict: Validated context with tenant, subscription, user info, resource_group, region
        """
        expected_tenant = AzureTenant.get(project)
        expected_sub = mc.cache.get(project, "AZURE_SUBSCRIPTION_ID")
        if not expected_sub:
            raise RuntimeError(f"[AzureUser] No AZURE_SUBSCRIPTION_ID cached for '{project}'")

        actual_tenant = cli_context.get("tenantId")
        actual_sub = cli_context.get("id")
        user_info = cli_context.get("user", {})
        user_type = user_info.get("type", "Unknown")

        # Validate user type
        if user_type.lower() != "user":
            raise RuntimeError(
                f"[AzureUser] ❌ Expected a user identity but got '{user_type}'. Please run `az logout`."
            )

        # Final tenant/sub checks
        if actual_tenant != expected_tenant:
            raise RuntimeError(
                f"[AzureUser] ❌ Tenant mismatch after fix: CLI={actual_tenant} vs Config={expected_tenant}"
            )
        if actual_sub != expected_sub:
            raise RuntimeError(
                f"[AzureUser] ❌ Subscription mismatch after fix: CLI={actual_sub} vs Config={expected_sub}"
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
    def help() -> None:
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