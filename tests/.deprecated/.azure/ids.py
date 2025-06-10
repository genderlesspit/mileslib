import logging
import time
from typing import Optional, Dict, Any

from milesazure.client import AzureClient
from milesazure.tenant import AzureUser
from context.milescontext import cache
from milesazure.run import run_az
from milesazure.vault import VaultSetup

logger = logging.getLogger(__name__)


class AzureIDs:
    """
    Lightweight wrapper for resolving Azure identity values from AzureUser and AzureClient context.
    Uses a single mapping function without redundant key lists.
    """
    _cache: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _load_contexts(project: str) -> None:
        """
        Loads and caches user_ctx and app_ctx for a project if not already cached.

        Steps:
            1. Check if 'project' is already in AzureIDs._cache; if so, return immediately.
            2. Call AzureUser.get(project) to retrieve user context (tenant_id, subscription_id, resource_group, region).
            3. Call AzureClient.get(project) to retrieve app context (appId, displayName, etc.).
            4. If either call returns None or incomplete data, raise a RuntimeError.
            5. Store both contexts in AzureIDs._cache[project], then log a debug message.
        """
        if project in AzureIDs._cache:
            return

        user_ctx = AzureUser.get(project)
        logger.info("[AzureIDs.debug] USER_CTX:", user_ctx)
        app_ctx = AzureClient.get(project)
        logger.info("[AzureIDs.debug] APP_CTX:", app_ctx)
        if not user_ctx or not app_ctx:
            raise RuntimeError(f"[AzureIDs] Error fetching Azure context for project '{project}'")

        AzureIDs._cache[project] = {"user_ctx": user_ctx, "app_ctx": app_ctx}
        logger.debug(f"[AzureIDs] Cached contexts for project '{project}'")

    @staticmethod
    def _mapping(project: str) -> Dict[str, Optional[str]]:
        """
        Returns a dict mapping all required Azure identity keys to their values.

        Keys returned:
            {
                "AZURE_TENANT_ID": str,
                "AZURE_SUBSCRIPTION_ID": str,
                "RESOURCE_GROUP": str,
                "AZURE_REGION": str,
                "AZURE_CLIENT_ID": str,
                "AZURE_CLIENT_SECRET": str
            }

        Implementation outline:
            1. Call AzureIDs._load_contexts(project) to ensure user_ctx and app_ctx are loaded.
            2. Pull tenant_id, subscription_id, resource_group, region from user_ctx.
            3. Pull appId from app_ctx to map to "AZURE_CLIENT_ID".
            4. Retrieve the client_secret from cache.temp_get(project, "client_secret").
            5. Return the assembled mapping.
        """
        logger.info("Attempting mapping!")
        AzureIDs._load_contexts(project)
        ctx = AzureIDs._cache[project]
        user = ctx["user_ctx"]
        app = ctx["app_ctx"]

        return {
            "AZURE_TENANT_ID": user.get("tenant_id"),
            "AZURE_SUBSCRIPTION_ID": user.get("subscription_id"),
            "RESOURCE_GROUP": user.get("resource_group"),
            "AZURE_REGION": user.get("region"),
            "AZURE_CLIENT_ID": app.get("appId"),
            "AZURE_CLIENT_SECRET": AzureClient.generate_secret(project),
            "SP_OBJECT_ID": AzureClient.ensure_service_principal(project, app.get("appId"))
        }

    @staticmethod
    def get(key: str, project: str, required: bool = True) -> Optional[str]:
        """
        Retrieve a specific Azure identity value for a given project.

        Args:
            key (str): One of the keys from AzureIDs._mapping(), e.g. "AZURE_TENANT_ID".
            project (str): Project name/identifier.
            required (bool): If True, raises RuntimeError when the key is missing or None.

        Returns:
            Optional[str]: The requested identity value, or None if not required and missing.

        Implementation outline:
            1. Call AzureIDs._mapping(project) to get the full dict.
            2. Look up mapping.get(key).
            3. If value is None and required=True, raise RuntimeError.
            4. Log a debug message and return the value.
        """
        mapping = AzureIDs._mapping(project)
        val = mapping.get(key)
        if val is None and required:
            raise RuntimeError(f"[AzureIDs] Missing required value for key '{key}' in project '{project}'")
        logger.debug(f"[AzureIDs] Retrieved '{key}' for project '{project}': {val}")
        return val

    @staticmethod
    def validate_all(project: str) -> Dict[str, str]:
        """
        Ensure that all identity values are present for a given project.

        Raises a RuntimeError listing any missing keys.

        Returns:
            Dict[str, str]: A map containing all required identity values (no None values).

        Implementation outline:
            1. Call AzureIDs._mapping(project) to assemble all key->value pairs.
            2. Identify any keys where the value is falsy (None or empty string).
            3. If any missing, raise RuntimeError with the list of missing keys.
            4. Otherwise, return the full mapping.
        """
        mapping = AzureIDs._mapping(project)
        missing = [k for k, v in mapping.items() if not v]
        if missing:
            raise RuntimeError(f"[AzureIDs] Missing required keys for project '{project}': {missing}")
        # At this point, all values are present and non-empty.
        return mapping  # type: ignore

    @staticmethod
    def clear_cache(project: Optional[str] = None) -> None:
        """
        Clear cached contexts. If project is provided, only clear that project's cache; otherwise, clear all.

        Args:
            project (Optional[str]): Specific project to clear. If None, clears entire cache.
        """
        if project:
            AzureIDs._cache.pop(project, None)
            logger.debug(f"[AzureIDs] Cleared cache for project '{project}'")
        else:
            AzureIDs._cache.clear()
            logger.debug("[AzureIDs] Cleared entire cache")

class AzureServicePrincipal:
    """
    Simplified resolver for Azure service principal context and Key Vault setup.
    Responsibilities:
      - Log in as service principal for a given project.
      - Ensure the Key Vault exists for the project.
      - Ensure the service principal has Contributor role on the project's resource group.
      - Ensure the service principal has Key Vault Administrator role on the project vault.
      - Provide an entry point to retrieve all relevant SP context in a cached dict.
    """
    _sp_context: Dict[str, Dict[str, str]] = {}

    def __init__(self, project):
        """
        Initialize (or retrieve) the service-principal context for `project`.

        Variables:
            identities: Dict[str, str]    # output of AzureIDs.validate_all
            tenant_id: str
            subscription_id: str
            client_id: str
            client_secret: str
            sp_object_id: str

        Sub-functions:
            _validate_identities()        # calls AzureIDs.validate_all(project)
            _login_sp()                   # calls run_az([... "az login" ...])
            _set_subscription()           # calls run_az([... "az account set" ...])

        Logic:
            1. If project already in AzureServicePrincipal._sp_context, return immediately.
            2. identities = AzureIDs.validate_all(project)
               - Raises if any identity is missing.
               - Expected keys: "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID",
                                "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "SP_OBJECT_ID"
            3. Extract tenant_id, subscription_id, client_id, client_secret, sp_object_id.
            4. Call AzureServicePrincipal.assign_rbac(sp_object_id, project)
               - Ensures SP has Contributor on the RG and Key Vault exists; also assigns Secrets User role.
            5. Call run_az to log in as SP:
                   az login --service-principal
                            --username <client_id>
                            --password <client_secret>
                            --tenant <tenant_id>
               - If run_az fails, raise RuntimeError with context.
            6. Call run_az to set subscription:
                   az account set --subscription <subscription_id>
               - If run_az fails, raise RuntimeError with context.
            7. Cache in _sp_context:
                   AzureServicePrincipal._sp_context[project] = {
                       "tenant_id": tenant_id,
                       "subscription_id": subscription_id,
                       "client_id": client_id,
                       "client_secret": client_secret
                   }
            8. Log info about successful initialization.
        """

        def recall_from_ids(k: str) -> str:
            logger.info(f"Attempting to fetch {k}...")
            v = AzureIDs.get(k, project)
            if v is not None: logger.info(f"Succesfully fetched {k}: {v}")
            return v

        ids = {
            key: cache.get(project, key, recall=recall_from_ids(key))
            for key in [
                "AZURE_TENANT_ID",
                "AZURE_SUBSCRIPTION_ID",
                "AZURE_CLIENT_ID",
                #"AZURE_CLIENT_SECRET",
                "RESOURCE_GROUP",
                "AZURE_REGION",
                "SP_OBJECT_ID",
            ]
        }
        if not isinstance(project, str) or not project.strip():
            raise TypeError("AzureServicePrincipal._init_sp_context: 'project' must be a non-empty string")

        if project in AzureServicePrincipal._sp_context:
            logger.debug("[AzureServicePrincipal] SP context for '%s' already initialized; skipping.", project)
            return

        self.project = project
        self.tenant_id = ids["AZURE_TENANT_ID"]
        self.subscription_id = ids["AZURE_SUBSCRIPTION_ID"]
        self.client_id = ids["AZURE_CLIENT_ID"]
        self.client_secret = AzureIDs.get("AZURE_CLIENT_SECRET", project)
        self.resource_group = ids["RESOURCE_GROUP"]
        self.region = ids["AZURE_REGION"]
        self.sp_object_id = ids["SP_OBJECT_ID"]
        self.vault_meta = VaultSetup.get_vault(self.project)

        logger.debug(
            "[AzureServicePrincipal] Retrieved identities for '%s': tenant=%s sub=%s client=%s",
            self.project, self.tenant_id, self.subscription_id, self.client_id
        )

        try:
            AzureServicePrincipal.assign_rbac(self)
        except Exception as ex:
            raise RuntimeError(f"[AzureServicePrincipal] RBAC assignment failed for '{self.project}': {ex}")

        try:
            run_az(
                [
                    "az", "login",
                    "--service-principal",
                    "--username", self.client_id,
                    "--password", self.client_secret,
                    "--tenant", self.tenant_id
                ],
                capture_output=False,
                json_override=False
            )
            logger.debug("[AzureServicePrincipal] Logged in as SP for project '%s'.", self.project)
        except Exception as ex:
            raise RuntimeError(f"[AzureServicePrincipal] Failed SP login for '{self.project}': {ex}")

        try:
            run_az(
                ["az", "account", "set", "--subscription", self.subscription_id],
                capture_output=False
            )
            logger.debug("[AzureServicePrincipal] Set subscription '%s' for project '%s'.", self.subscription_id, self.project)
        except Exception as ex:
            raise RuntimeError(f"[AzureServicePrincipal] Failed to set subscription for '{self.project}': {ex}")

    def assign_rbac(self) -> None:
        """
        Ensure the service principal has:
          - Contributor role on the project's Resource Group.
          - Key Vault Administrator role on the project's Key Vault.

        Variables:
            sub_id: str                   # subscription ID from AzureIDs.get
            rg: str                       # resource group name from AzureIDs.get
            rg_scope: str                 # "/subscriptions/{sub_id}/resourceGroups/{rg}"
            vault_id: str                 # full resource ID of the Key Vault

        Logic:
            1. sub_id = AzureIDs.get("AZURE_SUBSCRIPTION_ID", project, required=True)
            2. rg = AzureIDs.get("RESOURCE_GROUP", project, required=True)
            3. Build rg_scope = f"/subscriptions/{sub_id}/resourceGroups/{rg}"
            4. Ensure Key Vault exists: vault_meta = VaultSetup.get_vault(project)
               - This will create the vault if missing.
            5. vault_id = vault_meta["VAULT_ID"]
            6. Assign "Contributor" on rg_scope:
                   az role assignment create --assignee <sp_object_id> --role Contributor --scope rg_scope
               - Wait until assignment is visible.
            7. Assign "Key Vault Administrator" on vault_id:
                   az role assignment create --assignee-object-id <sp_object_id> --role "Key Vault Administrator" --scope vault_id
               - Wait until assignment is visible.
        """
        rg_scope = f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}"
        logger.debug(
            "[AzureServicePrincipal] assign_rbac: sub_id=%s, rg=%s, sp_object_id=%s",
            self.subscription_id, self.resource_group, self.sp_object_id
        )

        try:

            vault_id = self.vault_meta["VAULT_ID"]
            logger.debug(
                "[AzureServicePrincipal] Vault ensured for project '%s', vault_id='%s'.",
                self.project, vault_id
            )
        except Exception as ex:
            raise RuntimeError(f"[AzureServicePrincipal] Key Vault setup failed for '{self.project}': {ex}")

        def _assign_contributor():
            run_az(
                [
                    "az", "role", "assignment", "create",
                    "--assignee", self.sp_object_id,
                    "--role", "Contributor",
                    "--scope", rg_scope
                ],
                capture_output=True
            )

        def _assign_kv_admin():
            run_az(
                [
                    "az", "role", "assignment", "create",
                    "--assignee-object-id", self.sp_object_id,
                    "--role", "Key Vault Administrator",
                    "--scope", vault_id
                ],
                capture_output=True
            )

        def _check_role_assigned(role_name: str, scope: str) -> bool:
            """
            Returns True if the SP already has `role_name` on `scope`.
            Uses capture_output=True so run_az does *not* go through cmd.exe /c.
            """
            try:
                result = run_az(
                    [
                        "az", "role", "assignment", "list",
                        "--scope", scope,
                        "--query", f"[?principalId=='{self.sp_object_id}' && roleDefinitionName=='{role_name}']",
                        "--output", "json"
                    ],
                    capture_output=True
                )
                # `run_az` returns a Python list parsed from JSON, if any assignments exist.
                return isinstance(result, list) and len(result) > 0
            except Exception:
                # If something goes wrong, just return False and retry.
                return False

        # 1. Assign Contributor on the resource group
        try:
            logger.info(
                "[AzureServicePrincipal] Assigning 'Contributor' on '%s' to SP '%s'.",
                rg_scope, self.sp_object_id
            )
            _assign_contributor()
            logger.info("[AzureServicePrincipal] → Role 'Contributor' assignment triggered.")
        except Exception as ex:
            stderr = str(ex).lower()
            if "resourcenotfound" in stderr or "was not found" in stderr:
                raise RuntimeError(
                    f"[AzureServicePrincipal] Resource Group '{self.resource_group}' not found for '{self.project}': {ex}"
                )
            else:
                raise RuntimeError(
                    f"[AzureServicePrincipal] Role assignment (Contributor) failed for '{self.project}': {ex}"
                )

        # Wait loop for Contributor assignment to propagate
        max_wait = 60   # seconds
        interval = 5    # seconds
        waited = 0
        while waited < max_wait:
            if _check_role_assigned("Contributor", rg_scope):
                logger.info(
                    "[AzureServicePrincipal] Confirmed 'Contributor' role on '%s'.",
                    rg_scope
                )
                break
            logger.debug(
                "[AzureServicePrincipal] Waiting for 'Contributor' role on '%s' to propagate...",
                rg_scope
            )
            time.sleep(interval)
            waited += interval
        else:
            raise RuntimeError(
                f"[AzureServicePrincipal] Timed out waiting for 'Contributor' assignment on '{rg_scope}'"
            )

        # 2. Assign Key Vault Administrator on the vault
        try:
            logger.info(
                "[AzureServicePrincipal] Assigning 'Key Vault Administrator' on vault '%s' to SP '%s'.",
                vault_id, self.sp_object_id
            )
            _assign_kv_admin()
            logger.info("[AzureServicePrincipal] → Role 'Key Vault Administrator' assignment triggered.")
        except Exception as ex:
            stderr = str(ex).lower()
            if "already exists" in stderr or "exists" in stderr:
                logger.info(
                    "[AzureServicePrincipal] 'Key Vault Administrator' role already assigned; skipping."
                )
            else:
                raise RuntimeError(
                    f"[AzureServicePrincipal] Role assignment (Key Vault Administrator) failed for '{self.project}': {ex}"
                )

        # Wait loop for Key Vault Administrator assignment to propagate
        waited = 0
        while waited < max_wait:
            if _check_role_assigned("Key Vault Administrator", vault_id):
                logger.info(
                    "[AzureServicePrincipal] Confirmed 'Key Vault Administrator' role on vault '%s'.",
                    vault_id
                )
                break
            logger.debug(
                "[AzureServicePrincipal] Waiting for 'Key Vault Administrator' role on vault '%s' to propagate...",
                vault_id
            )
            time.sleep(interval)
            waited += interval
        else:
            raise RuntimeError(
                f"[AzureServicePrincipal] Timed out waiting for 'Key Vault Administrator' assignment on vault '{vault_id}'"
            )