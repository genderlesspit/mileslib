import logging
from typing import Optional, Dict, Any

from azure.client import AzureClient
from azure.tenant import AzureUser
from backend_methods import backend_methods
from context.milescontext import cache

logger = logging.getLogger(__name__)


class AzureIDs:
    """
    Lightweight wrapper for resolving Azure identity values from the validated AzureUser and AzureClient contexts.
    This version caches user and app contexts per project to avoid repeated lookups.
    """

    # Class-level cache: { project_name: { "user_ctx": dict, "app_ctx": dict } }
    _cache: Dict[str, Dict[str, Any]] = {}

    REQUIRED_KEYS = {
        "AZURE_TENANT_ID": "Tenant ID",
        "AZURE_SUBSCRIPTION_ID": "Subscription ID",
        "AZURE_CLIENT_ID": "Client ID",
        "AZURE_CLIENT_SECRET": "Client Secret",
        "RESOURCE_GROUP": "Azure Resource Group",
        "AZURE_REGION": "Azure Region",
        "DB_NAME": "Database Name"
    }

    @staticmethod
    def _load_contexts(project: str) -> None:
        """
        Helper that loads and caches user_ctx and app_ctx for a project if not already cached.

        Variables:
            cached (dict): The existing cache entry for this project, if any.
            user_ctx (dict): The AzureUser context returned by AzureUser.get(project).
            app_ctx (dict): The AzureClient context returned by AzureClient.get(project).

        Logic:
            1. Check if project is already in _cache.
            2. If not, call AzureUser.get(project) and AzureClient.get(project) to retrieve contexts.
            3. If either context is missing or invalid, raise RuntimeError.
            4. Store both contexts in the class-level _cache under this project key.
        """
        cached = AzureIDs._cache.get(project)
        if cached:
            return

        user_ctx = AzureUser.get(project)
        app_ctx = AzureClient.get(project)

        if not user_ctx or not app_ctx:
            message = f"[AzureIDs] Could not retrieve user or app context for project '{project}'!"
            logger.error(message)
            raise RuntimeError(message)

        AzureIDs._cache[project] = {
            "user_ctx": user_ctx,
            "app_ctx": app_ctx
        }
        logger.debug(f"[AzureIDs] Cached user_ctx and app_ctx for project '{project}'")

    @staticmethod
    def get(key: str, project: str, required: bool = True) -> Optional[str]:
        """
        Retrieve a specific Azure identity value for a given project, using an internal cache.

        Args:
            key (str): One of the keys from REQUIRED_KEYS (e.g., "AZURE_TENANT_ID").
            project (str): The project namespace to use when looking up contexts.
            required (bool): If True and the value is missing, raise RuntimeError; otherwise return None.

        Returns:
            Optional[str]: The requested identity value, or None if not found and required=False.

        Variables:
            cache_entry (dict): Cached contexts for this project.
            user_ctx (dict): Cached AzureUser context.
            app_ctx (dict): Cached AzureClient context.
            secret (str): Retrieved client_secret from temporary cache if applicable.
            db_name (str): Retrieved database name via backend_methods.putil.db_name(project).
            mapping (dict): Maps keys to their resolved values.
            val (Optional[str]): The final value looked up from mapping.

        Logic:
            1. Call _load_contexts(project) to ensure user_ctx and app_ctx are cached.
            2. Retrieve cache_entry = AzureIDs._cache[project].
            3. Pull user_ctx and app_ctx from cache_entry.
            4. Build a mapping of all possible keys to their values.
            5. Look up val = mapping.get(key).
            6. If val is None and required=True, log and raise RuntimeError.
            7. Return val (or None if not found and required=False).
        """
        AzureIDs._load_contexts(project)
        cache_entry = AzureIDs._cache[project]

        user_ctx = cache_entry["user_ctx"]
        app_ctx = cache_entry["app_ctx"]

        secret = cache.temp_get(project, "client_secret")
        db_name = backend_methods.putil.db_name(project)

        mapping = {
            "AZURE_TENANT_ID": user_ctx.get("tenant_id"),
            "AZURE_SUBSCRIPTION_ID": user_ctx.get("subscription_id"),
            "RESOURCE_GROUP": user_ctx.get("resource_group"),
            "AZURE_REGION": user_ctx.get("region"),
            "AZURE_CLIENT_ID": app_ctx.get("appId"),
            "AZURE_CLIENT_SECRET": secret,
            "DB_NAME": db_name
        }

        val = mapping.get(key)
        if val is None and required:
            message = f"[AzureIDs] Missing required value for key '{key}' in project '{project}'"
            logger.error(message)
            raise RuntimeError(message)

        logger.debug(f"[AzureIDs] Retrieved key '{key}' for project '{project}': {val}")
        return val

    @staticmethod
    def validate_all(project: str) -> Dict[str, str]:
        """
        Ensure that all required identity values are present for a given project.

        Args:
            project (str): The project namespace to validate.

        Returns:
            Dict[str, str]: A dictionary mapping each required key to its resolved value.

        Variables:
            result (dict): Accumulates the validated key-value pairs.

        Logic:
            1. Log that validation is starting.
            2. Iterate over all keys in REQUIRED_KEYS.
            3. For each key, call AzureIDs.get(key, project=project, required=True).
            4. Collect returned values into result.
            5. Return result.
        """
        logger.info(f"[AzureIDs] Validating all required identity values for project '{project}'")
        result: Dict[str, str] = {}
        for key in AzureIDs.REQUIRED_KEYS:
            result[key] = AzureIDs.get(key, project=project, required=True)
        logger.info(f"[AzureIDs] Validation complete for project '{project}'")
        return result

    @staticmethod
    def clear_cache(project: Optional[str] = None) -> None:
        """
        Clear cached contexts. If project is provided, only clear that project's cache; otherwise, clear all.

        Args:
            project (Optional[str]): Specific project to clear from cache. If None, clear entire cache.

        Variables:
            _ (Any): Temporary variable when iterating patterns (unused).

        Logic:
            1. If project is None, reinitialize _cache to an empty dict.
            2. If project key exists in _cache, delete that entry.
            3. Log cache clearing actions.
        """
        if project is None:
            AzureIDs._cache = {}
            logger.debug("[AzureIDs] Cleared entire cache")
        else:
            if project in AzureIDs._cache:
                del AzureIDs._cache[project]
                logger.debug(f"[AzureIDs] Cleared cache for project '{project}'")
            else:
                logger.debug(f"[AzureIDs] No cache entry to clear for project '{project}'")
