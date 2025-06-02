import logging
from typing import Optional, Dict, Any

from milesazure.client import AzureClient
from milesazure.database import DatabaseSetup
from milesazure.tenant import AzureUser
from backend_methods import backend_methods
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
        app_ctx = AzureClient.get(project)
        if not user_ctx or not app_ctx:
            raise RuntimeError(f"[AzureIDs] Missing Azure context for project '{project}'")

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
            "AZURE_CLIENT_SECRET": cache.temp_get(project, "client_secret"),
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

class AzureServices:
    """
    Centralized resolver for Azure service-specific names, URIs, and naming quirks,
    including Key Vault and PostgreSQL metadata. Before resolving any metadata, this class
    ensures that the service-principal is logged in (via `sp_context`) and that all AzureIDs are valid.

    Structure mimics AzureIDs:
      - _sp_context: caches per-project SP login context/credentials
      - _init_sp_context(): validate identities + login as SP
      - _mapping(): combines vault, database, and other static service conventions
      - get(): fetch a single service key
      - validate_all(): ensure no missing service keys
    """
    _sp_context: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _init_sp_context(project: str) -> None:
        """
        Initialize (or retrieve) the service-principal context for `project` and log in as the SP.

        Steps:
            1. If project already in AzureServices._sp_context, do nothing.
            2. Call AzureIDs.validate_all(project) to retrieve:
                   - AZURE_TENANT_ID
                   - AZURE_SUBSCRIPTION_ID
                   - AZURE_CLIENT_ID
                   - AZURE_CLIENT_SECRET
            3. Use run_az(...) to perform:
                   az login --service-principal --username <client_id> --password <client_secret> --tenant <tenant_id>
            4. Use run_az(...) to set the subscription:
                   az account set --subscription <subscription_id>
            5. On success, store a dict with at least:
                   {
                     "tenant_id": str,
                     "subscription_id": str,
                     "client_id": str,
                     "client_secret": str
                   }
               in AzureServices._sp_context[project].
            6. Log debug messages at each step. If any call fails, raise RuntimeError.
        """
        if project in AzureServices._sp_context:
            return  # Already initialized

        # Step 2: Validate all identity values
        identities = AzureIDs.validate_all(project)
        tenant_id = identities["AZURE_TENANT_ID"]
        subscription_id = identities["AZURE_SUBSCRIPTION_ID"]
        client_id = identities["AZURE_CLIENT_ID"]
        client_secret = identities["AZURE_CLIENT_SECRET"]
        sp_object_id =  identities["SP_OBJECT_ID"]

        # Step 2.5 Assign RBAC.
        AzureServices.assign_rbac(sp_object_id, project)

        # Step 3: Login as service principal
        try:
            run_az([
                "az", "login",
                "--service-principal",
                "--username", client_id,
                "--password", client_secret,
                "--tenant", tenant_id
            ])
            logger.debug(f"[AzureServices] Logged in as SP for project '{project}'.")
        except Exception as ex:
            raise RuntimeError(f"[AzureServices] Failed SP login for project '{project}': {ex}")

        # Step 4: Set subscription
        try:
            run_az([
                "az", "account", "set",
                "--subscription", subscription_id
            ])
            logger.debug(f"[AzureServices] Set subscription '{subscription_id}' for project '{project}'.")
        except Exception as ex:
            raise RuntimeError(f"[AzureServices] Failed to set subscription for project '{project}': {ex}")

        # Step 5: Cache the SP context
        AzureServices._sp_context[project] = {
            "tenant_id": tenant_id,
            "subscription_id": subscription_id,
            "client_id": client_id,
            "client_secret": client_secret
        }

    @staticmethod
    def assign_rbac(sp_object_id: str, project: str) -> None:
        """
        For the service principal identified by `sp_object_id`, assign all RBAC roles needed to manage the stack.
        If the target resource doesn't exist, create it first and then retry the assignment.
        """
        sub_id = AzureIDs.get("AZURE_SUBSCRIPTION_ID", project)
        rg     = AzureIDs.get("RESOURCE_GROUP", project)

        # Build each scope string
        rg_scope = f"/subscriptions/{sub_id}/resourceGroups/{rg}"
        vault_scope = (
            f"/subscriptions/{sub_id}/resourceGroups/{rg}"
            f"/providers/Microsoft.KeyVault/vaults/{project.lower()}-vault"
        )
        db_scope = (
            f"/subscriptions/{sub_id}/resourceGroups/{rg}"
            f"/providers/Microsoft.DBforPostgreSQL/flexibleServers/{project.lower()}-db"
        )

        # (You could add storage_scope, func_scope, etc. in the same pattern.)
        assignments = [
            # (scope, role_name, create_callback)
            (rg_scope,    "Contributor",               None),  # RG should always exist
            (vault_scope, "Key Vault Contributor",      VaultSetup.create_vault),
            (db_scope,    "Contributor",               DatabaseSetup.create_postgres),
        ]

        for scope, role_name, create_fn in assignments:
            AzureServices._assign_role_with_fallback(
                sp_object_id, project, scope, role_name, create_fn
            )

        logger.info("[AzureServices] ✅ All RBAC assignments complete.")

    @staticmethod
    def _assign_role_with_fallback(
        sp_object_id: str,
        project: str,
        scope: str,
        role_name: str,
        create_fn: callable = None
    ) -> None:
        """
        Attempt to assign `role_name` on `scope` to the SP. If Azure returns ResourceNotFound,
        call `create_fn(project)` (if provided), then retry the same role assignment once.
        """
        def _do_assignment() -> None:
            run_az(
                [
                    "az", "role", "assignment", "create",
                    "--assignee", sp_object_id,
                    "--role",     role_name,
                    "--scope",    scope,
                ],
                capture_output=False
            )

        try:
            logger.info(f"[AzureServices] Assigning '{role_name}' on '{scope}' to SP {sp_object_id}")
            _do_assignment()
            logger.debug(f"[AzureServices] → Success: '{role_name}' on '{scope}'")
        except Exception as ex:
            stderr = str(ex).lower()
            # Detect a missing-resource error (PostgreSQL or KeyVault not found)
            if create_fn and ("resourcenotfound" in stderr or "was not found" in stderr):
                logger.warning(f"[AzureServices] Resource at '{scope}' not found. "
                               f"Calling creation callback and retrying…")
                try:
                    # create_fn must be a function that takes (project) and returns
                    # once the resource is in place—e.g. VaultSetup.create_vault or DatabaseSetup.create_postgres
                    if create_fn is VaultSetup.create_vault:
                        # VaultSetup.create_vault returns a dict with "name" and "uri",
                        # but we only care that the vault ends up existing.
                        create_fn(project)
                    else:
                        # For DatabaseSetup.create_postgres, it returns metadata dict.
                        create_fn(project)

                    # Now retry the assignment one more time
                    logger.info(f"[AzureServices] Retrying '{role_name}' on '{scope}' after creation")
                    _do_assignment()
                    logger.debug(f"[AzureServices] → Success on retry: '{role_name}' on '{scope}'")
                except Exception as ex2:
                    logger.error(f"[AzureServices] Failed to both create resource at '{scope}' and assign role: {ex2}")
                    raise RuntimeError(f"Could not create resource‐and‐assign '{role_name}' on '{scope}': {ex2}")
            else:
                # Any other failure type we bubble up
                logger.error(f"[AzureServices] Could not assign '{role_name}' on '{scope}': {ex}")
                raise

    @staticmethod
    def get_vault_metadata(project: str) -> Dict[str, str]:
        """
        Retrieve Key Vault metadata for the given project by simply calling
        VaultSetup.get_vault(project). If VaultSetup.get_vault(...) raises,
        the error is propagated unchanged.

        Returns:
            {
                "VAULT_NAME": str,
                "VAULT_URI": str,
                "VAULT_LOCATION": str,
                "VAULT_ID": str,
                # (plus any additional fields VaultSetup.get_vault() provides)
            }
        """
        AzureServices._init_sp_context(project)

        # Delegates entirely to vault.py's VaultSetup.get_vault(...)
        try:
            vault_meta = VaultSetup.get_vault(project)
            logger.info(f"[AzureServices] Fetched vault metadata for '{project}': {vault_meta}")
            return {
                "VAULT_NAME": vault_meta.get("VAULT_NAME"),
                "VAULT_URI": vault_meta.get("VAULT_URI"),
                "VAULT_LOCATION": vault_meta.get("VAULT_LOCATION"),
                "VAULT_ID": vault_meta.get("VAULT_ID"),
            }
        except Exception as e:
            # Let VaultSetup.raise its own RuntimeError if it fails
            raise

    @staticmethod
    def get_postgresql_metadata(project: str) -> Dict[str, str]:
        """
        Ensure a PostgreSQL flexible server exists and is reachable for `project`.

        Returns a dict containing at least:
            {
                "DB_SERVER_NAME": str,
                "DB_FQDN": str,
                "DB_LOCATION": str,
                "DB_ID": str,
                "admin_login": str
            }

        Implementation outline:
            1. Call AzureServices._init_sp_context(project) to ensure SP is logged in.
            2. Import milesazure.database.DatabaseSetup.
            3. Call DatabaseSetup.ensure_postgres_ready(project) which should:
                   - Create or retrieve an existing PostgreSQL flexible server.
                   - Return the required metadata dictionary.
            4. Return whatever DatabaseSetup.ensure_postgres_ready(...) returns.
            5. If it raises, propagate or wrap in a RuntimeError.
        """
        AzureServices._init_sp_context(project)
        try:
            return DatabaseSetup.ensure_postgres_ready(project)
        except Exception as e:
            raise RuntimeError(f"[AzureServices] Failed to get PostgreSQL metadata for '{project}': {e}")

    @staticmethod
    def _mapping(project: str) -> Dict[str, str]:
        """
        Combine vault metadata, PostgreSQL metadata, and other static service conventions into one map.

        Returns a dict with keys:
            - "VAULT_NAME", "VAULT_URI", "VAULT_LOCATION", "VAULT_ID"
            - "DB_SERVER_NAME", "DB_FQDN", "DB_LOCATION", "DB_ID", "admin_login"
            - "STORAGE_ACCOUNT", "STATIC_CONTAINER", "FUNCTION_APP_NAME", "FUNCTION_STORAGE"

        Implementation outline:
            1. Normalize project name: p = project.lower().
            2. Prepare a static_map for storage/function naming conventions.
            3. Call get_vault_metadata(project) to retrieve vault_map.
            4. Call get_postgresql_metadata(project) to retrieve db_map.
            5. Merge all three dicts (vault_map, db_map, static_map) into one and return.
        """
        p = project.lower()
        static_map = {
            "STORAGE_ACCOUNT": f"{p}storage",
            "STATIC_CONTAINER": "$web",
            "FUNCTION_APP_NAME": f"{p}-func",
            "FUNCTION_STORAGE": f"{p}storage",
        }

        vault_map = AzureServices.get_vault_metadata(project)
        db_map = AzureServices.get_postgresql_metadata(project)
        combined = {**vault_map, **db_map, **static_map}
        return combined

    @staticmethod
    def get(key: str, project: str, required: bool = True) -> Optional[str]:
        """
        Retrieve a specific Azure service or vault value for a given project.

        Args:
            key (str): Name of the service key to fetch (e.g. "VAULT_URI", "DB_FQDN", "FUNCTION_APP_NAME").
            project (str): Project name/identifier.
            required (bool): If True, raises RuntimeError when the key is missing or empty.

        Returns:
            Optional[str]: The requested service value, or None if not required and missing.

        Implementation outline:
            1. Call AzureServices._mapping(project) to get the full dict.
            2. Look up mapping.get(key).
            3. If value is None or empty string and required=True, raise RuntimeError.
            4. Log a debug message showing the resolved value.
            5. Return the value.
        """
        mapping = AzureServices._mapping(project)
        val = mapping.get(key)
        if (val is None or val == "") and required:
            raise RuntimeError(f"[AzureServices] Missing required value for key '{key}' in project '{project}'")
        logger.debug(f"[AzureServices] Resolved '{key}' for project '{project}': {val}")
        return val

    @staticmethod
    def validate_all(project: str) -> Dict[str, str]:
        """
        Return all service, vault, and PostgreSQL values for a given project; raise if any are missing.

        Returns:
            Dict[str, str]: A map containing all required service values (none empty).

        Implementation outline:
            1. Call AzureServices._mapping(project).
            2. Identify any keys where the value is falsy (None or empty string).
            3. If any missing, raise RuntimeError listing them.
            4. Otherwise return the full mapping.
        """
        mapping = AzureServices._mapping(project)
        missing = [k for k, v in mapping.items() if not v]
        if missing:
            raise RuntimeError(f"[AzureServices] Missing required keys for project '{project}': {missing}")
        return mapping  # type: ignore
