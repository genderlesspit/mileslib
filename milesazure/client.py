import json
import logging
from typing import Dict, Optional, Any

from milesazure import tenant  # tenant.user, tenant.tenant_id, tenant.subscription_id
from milesazure.run import run_az
import milesazure.run as run
from context import milescontext as mc  # mc.cache is the Cache instance
from milesazure.tenant import AzureSubscription
from util.error_handling import recall

logger = logging.getLogger(__name__)

class AzureClient:
    """
    Handles provisioning of the Azure app registration, service principal, global-admin assignment,
    and temporary client secret storage for a given project.
    """

    @staticmethod
    def get(project: str) -> Dict[str, Any]:
        """
        Retrieve (or create) the AAD application for `project`, ensure its service principal has
        Global Administrator privileges, and guarantee a temporary client secret is cached.

        Args:
            project (str): The project namespace used for caching and naming.

        Returns:
            Dict[str, Any]: The AAD application dictionary (at minimum containing "appId").

        Variables:
            user_context (dict): The result of `tenant.user(project)`.
            username (str): Username extracted from user_context.
            t_id (str): Tenant ID fetched from cache or via `tenant.tenant_id(project)`.
            s_id (str): Subscription ID fetched from cache or via `tenant.subscription_id(project)`.
            full_display_name (str): Name for the AAD application: "<project>-app".
            cached_app_id (Optional[str]): Possibly cached application ID from mc.cache.get.
            app (dict): The AAD application object returned by `az ad app show`.
            app_id (str): The GUID of the AAD application.
            sp_object_id (str): Service Principal object ID; returned by ensure_service_principal.
            existing_secret (Optional[str]): Any existing temp client secret in mc.cache.

        Sub-functions:
            fetch_tenant_and_subscription():
                Loads tenant_id and subscription_id into `t_id` and `s_id` via cache with recall.
            get_or_create_app():
                Checks for a cached app_id. If present, calls verify_app(); if verify fails or no cache,
                creates a new AAD app. Finally, always sets `app` and `app_id`.

        Logic:
            1. Load logged-in user via tenant.user(project) and log username.
            2. Fetch or recall tenant_id and subscription_id.
            3. Determine full_display_name = f"{project}-app".
            4. Attempt to retrieve a cached app_id; if missing or invalid, create a new app.
            5. Ensure a Service Principal exists for the app_id.
            6. Assign Global Administrator role to that Service Principal.
            7. Check mc.cache.temp_get for an existing "client_secret"; if missing, generate one now.
            8. Return the AAD app dictionary.
        """
        # ─────────────────────────────
        # All defined variables
        # ─────────────────────────────
        user_context: Dict[str, Any] = tenant.user(project)
        username: str = user_context.get("user", {}).get("name", "<unknown>")
        t_id: Optional[str] = None
        s_id: Optional[str] = None
        full_display_name: Optional[str] = None
        cached_app_id: Optional[str] = None
        app: Optional[Dict[str, Any]] = None
        app_id: Optional[str] = None
        sp_object_id: Optional[str] = None
        existing_secret: Optional[str] = None

        # ─────────────────────────────
        # Sub-functions
        # ─────────────────────────────
        def fetch_tenant_and_subscription() -> None:
            """
            Load tenant_id and subscription_id into t_id and s_id from cache (with recall lambdas).
            """
            nonlocal t_id, s_id
            t_id = mc.cache.get(
                project,
                "tenant_id",
                recall=lambda: tenant.tenant_id(project)
            )
            s_id = mc.cache.get(
                project,
                "subscription_id",
                recall=lambda: tenant.subscription_id(project)
            )

        def get_or_create_app() -> None:
            """
            Populate `app` and `app_id`. If a cached_app_id exists, verify it; otherwise create a new app.
            """
            nonlocal app, app_id, cached_app_id
            full = f"{project}-app"
            try: cached_app_id = mc.cache.get(project, "app_id")
            except Exception:
                print(f"[AzureClient] Could not retrieve AppID for {project}")
                pass

            print("[AzureClient] Could not find app_id. Attempting to create!")

            if cached_app_id:
                app = AzureClient.verify_app(project, full, cached_app_id)
                if app:
                    # verify_app may return either {"appId": ..., ...} or {"app_id": ...}
                    app_id = app.get("appId") or app.get("app_id")
                if not app:
                    # Cached ID was invalid or verify failed → create anew
                    app_id = AzureClient.create_app(project, full)
                    app = run.app_show(project)
            else:
                # No cached app_id → create a new AAD application
                app_id = AzureClient.create_app(project, full)
                app = run.app_show(project)

        # ─────────────────────────────
        # Logic
        # ─────────────────────────────
        logger.info(f"[AzureClient] Logged-in user: {username}")

        # 1. Fetch tenant/subscription IDs
        fetch_tenant_and_subscription()
        logger.info(
            f"[AzureClient] Using tenant_id={t_id!r}, subscription_id={s_id!r}"
        )

        # 2. Determine display name
        full_display_name = f"{project}-app"

        # 3. Retrieve or create AAD application
        get_or_create_app()

        if not app_id:
            raise RuntimeError(
                "[AzureClient] Failed to retrieve or create appId from AAD response."
            )

        # 4. Ensure a Service Principal exists
        sp_object_id = AzureClient.ensure_service_principal(project, app_id)
        #5.5 Assign Global Administrator role
        #5.9 Assign RBAC

        # 6. Ensure a temporary client secret is cached
        existing_secret = mc.cache.temp_get(project, "client_secret")
        if not existing_secret:
            logger.info(
                f"[AzureClient] No temp-secret found for project '{project}'; generating a new one."
            )
            # Directly call run_az to reset the credential (avoiding recursion)
            try:
                result = run_az([
                    "az", "ad", "app", "credential", "reset",
                    "--id", app_id,
                    "--append",
                    "--display-name", f"{project}-temp-secret"
                ])
            except Exception as ex:
                raise RuntimeError(
                    f"[AzureClient] Failed to create client secret: {ex}"
                )

            client_secret: Optional[str] = result.get("password")
            if not client_secret:
                raise RuntimeError(
                    "[AzureClient] Secret generation succeeded but 'password' missing."
                )

            mc.cache.temp_set(project, "client_secret", client_secret)
            logger.info(
                f"[AzureClient] 🔐 Temporary client secret stored in memory for '{project}'"
            )

        logger.info(
            f"[AzureClient] Application setup complete: appId={app_id}, spObjectId={sp_object_id}"
        )
        return app

    @staticmethod
    def verify_app(project: str, display_name: str, app_id: str) -> Optional[Dict[str, Any]]:
        """
        Verify that an AAD application with `app_id` still exists and has the correct `display_name`.
        If it exists and matches, returns the application dictionary. Otherwise returns None.

        Args:
            project (str): The project namespace.
            display_name (str): Expected AAD app display name.
            app_id (str): Candidate application ID to verify.

        Returns:
            Optional[Dict[str, Any]]: The AAD application dict if valid, else None.

        Variables:
            candidate_app (dict): The result of `az ad app show --id app_id`.
            actual_name (str): The "displayName" field from candidate_app.
        """
        try:
            candidate_app: Dict[str, Any] = run_az(["az", "ad", "app", "show", "--id", app_id])
        except Exception:
            logger.warning(f"[AzureClient] App with ID {app_id} not found; will recreate.")
            return None

        actual_name: str = candidate_app.get("displayName", "")
        if actual_name != display_name:
            logger.warning(
                f"[AzureClient] App displayName mismatch: expected={display_name}, actual={actual_name}. Recreating."
            )
            return None

        return candidate_app

    @staticmethod
    def create_app(project: str, display_name: str) -> str:
        """
        Create a new AAD application with the given `display_name`, cache its app_id, and return it.

        Args:
            project (str): The project namespace.
            display_name (str): The display name to assign to the new app.

        Returns:
            str: The newly created AAD application's GUID.

        Variables:
            create_resp (dict): Result from `run.app_create(display_name)`.
            new_app_id (str): Extracted "appId" from create_resp.
        """
        # --- All defined variables ---
        create_resp: dict
        new_app_id: str

        # --- Logic ---
        # Call the wrapper that invokes `az ad app create`
        create_resp = run.app_create(display_name)
        logger.debug(f"[AzureClient.create_app] Raw response from az ad app create: {create_resp!r}")

        # Validate that we got a dict back
        if not isinstance(create_resp, dict):
            raise RuntimeError(f"[AzureClient.create_app] Expected dict from run.app_create(), got {type(create_resp).__name__!r}")

        # Extract the "appId" field
        new_app_id = create_resp.get("appId")
        if not new_app_id or not isinstance(new_app_id, str):
            raise RuntimeError(f"[AzureClient.create_app] Could not find a valid 'appId' in response: {create_resp!r}")

        # Cache the app_id under the given project namespace
        try:
            mc.cache.set(project, "app_id", new_app_id, include_in_cfg=project)
        except Exception as ex:
            logger.error(f"[AzureClient.create_app] Failed to cache app_id: {ex}", exc_info=True)
            raise

        logger.info(f"[AzureClient.create_app] Created AAD app '{display_name}' with appId={new_app_id!r} and cached under '{project}'")

        return new_app_id

    @staticmethod
    def ensure_service_principal(project: str, app_id: str) -> str:
        """
        Ensure that a Service Principal exists for the AAD application with `app_id`.
        Returns the Service Principal's object ID. If an existing SP is found but lacks
        `objectId`, re-fetch via `az ad sp show --id` or recreate the SP.

        Args:
            project (str): The project name.
            app_id (str): The GUID of the AAD application.

        Returns:
            str: The Service Principal object ID.

        Variables:
            sp_via_show (dict): Result from `az ad sp show --id app_id`, if any.
            sp_list (list): Result from `az ad sp list --filter "appId eq '{app_id}'"`.
            candidate (dict): The first element of sp_list, if sp_list is non-empty.
            sp_obj_id (str): The `"objectId"` extracted from candidate or sp_via_show.
            create_sp (dict): Result from `az ad sp create --id app_id`, if we must create anew.

        Sub-functions:
            _fetch_sp_via_show() -> Optional[dict]:
                - Attempts `az ad sp show --id app_id`.
                - If succeeds, returns the SP dict; if not, returns None.

            _fetch_sp_via_list() -> Optional[dict]:
                - Attempts `az ad sp list --filter "appId eq '{app_id}'"`.
                - If list is non-empty, returns the first element; else returns None.

            _extract_object_id(sp_dict: dict) -> Optional[str]:
                - Safely pulls `"objectId"` or `"id"` from the SP dict.
                - Returns objectId if present, else None.

            _create_new_sp() -> str:
                - Calls `az ad sp create --id app_id`.
                - Raises on failure; returns the new SP's objectId.

        Logic:
            1. Try `_fetch_sp_via_show()`. If it returns a dict with a valid objectId, return that.
            2. Otherwise, try `_fetch_sp_via_list()`. If found, extract objectId; if valid, return it.
            3. If candidate exists but lacks objectId, fall back to `_fetch_sp_via_show()` again.
            4. If still no objectId, call `_create_new_sp()` to make a new SP, then return its objectId.
        """

        def _fetch_sp_via_show() -> Optional[Dict[str, Any]]:
            result = run_az(
                ["az", "ad", "sp", "show", "--id", app_id],
                ignore_errors={"not_found": ["does not exist", "not present"]}
            )
            return result or None

        def _fetch_sp_via_list() -> Optional[Dict[str, Any]]:
            sp_list = run_az(
                [
                    "az", "ad", "sp", "list",
                    "--filter", f"appId eq '{app_id}'"
                ],
                ignore_errors={"not_found": ["does not exist", "not present", "No matching"]}  # loose filter
            )
            if isinstance(sp_list, list) and sp_list:
                return sp_list[0]
            return None


        def _extract_object_id(sp_dict: Dict[str, Any]) -> Optional[str]:
            return sp_dict.get("objectId") or sp_dict.get("id")

        def _create_new_sp() -> str:
            try:
                create_sp = run_az(["az", "ad", "sp", "create", "--id", app_id])
            except Exception as ex:
                raise RuntimeError(
                    f"[AzureClient] Failed to create Service Principal for appId={app_id}: {ex}"
                )
            new_obj_id = _extract_object_id(create_sp)
            if not new_obj_id:
                raise RuntimeError(
                    f"[AzureClient] SP creation succeeded but no objectId returned for appId={app_id}."
                )
            logger.info(f"[AzureClient] Created new Service Principal with objectId={new_obj_id}")
            return new_obj_id

        def verify(sp_object_id, project):
            try:
                AzureClient.assign_global_admin(sp_object_id, project)
                AzureClient.assign_rbac(sp_object_id, project)
            except Exception as e:
                raise RuntimeError(f"{e}")
            return sp_object_id

        # ─────────────────────────────
        # 1. Attempt 'show' lookup
        # ─────────────────────────────
        sp_via_show = _fetch_sp_via_show()
        if sp_via_show:
            sp_obj_id = _extract_object_id(sp_via_show)
            if sp_obj_id:
                logger.debug(f"[AzureClient] Found SP via 'show' with objectId={sp_obj_id}")
                return sp_obj_id
            logger.warning(f"[AzureClient] SP record via 'show' lacked objectId for appId={app_id}")

        # ─────────────────────────────
        # 2. Attempt 'list' lookup
        # ─────────────────────────────
        candidate = _fetch_sp_via_list()
        if candidate:
            sp_obj_id = _extract_object_id(candidate)
            if sp_obj_id:
                logger.debug(f"[AzureClient] Found SP via 'list' with objectId={sp_obj_id}")
                verify(sp_obj_id, project)
                return sp_obj_id
            logger.warning(
                f"[AzureClient] SP entry from 'list' lacked objectId for appId={app_id}. "
                "Falling back to 'show' or creation."
            )

        # ─────────────────────────────
        # 3. Retry 'show' again
        # ─────────────────────────────
        sp_via_show_again = _fetch_sp_via_show()
        if sp_via_show_again:
            sp_obj_id = _extract_object_id(sp_via_show_again)
            if sp_obj_id:
                logger.debug(f"[AzureClient] Found SP via 'show' (retry) with objectId={sp_obj_id}")
                verify(sp_obj_id, project)
                return sp_obj_id

        # ─────────────────────────────
        # 4. Create new SP
        # ─────────────────────────────
        sp_obj_id = _create_new_sp()
        verify(sp_obj_id, project)
        return sp_obj_id

    @staticmethod
    def assign_global_admin(sp_object_id: str, project: str) -> None:
        """
        Assign the Azure AD Global Administrator role to the given Service Principal (objectId),
        using Microsoft Graph via `az rest`. If a conflicting assignment already exists,
        ignore that specific error and continue.

        Steps:
            1. Build the JSON body for creating a new roleAssignment.
            2. Call `run_az([...], ignore_errors={...})` so that if Graph returns
               a “conflicting object” error, it is swallowed.
            3. On any other failure, raise a RuntimeError.

        Args:
            sp_object_id (str): The Service Principal’s objectId.
            project (str): The project namespace (for logging).

        Variables:
            GA_ROLE_ID (str): Fixed GUID for Global Administrator.
            body (dict): JSON payload for the Graph POST.
            ignore_patterns (dict): Key→list of substrings to match in stderr, to swallow.
        """
        GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
        logger.info(f"[AzureClient] Assigning Global Administrator role to SP {sp_object_id}")

        # Build request body
        body = {
            "principalId": sp_object_id,
            "roleDefinitionId": GA_ROLE_ID,
            "directoryScopeId": "/"
        }

        # Any stderr containing "conflicting object" should be ignored
        ignore_patterns = {
            "roleAssignmentConflict": [
                "a conflicting object with one or more of the specified property values is present"
            ]
        }

        try:
            run_az(
                [
                    "az", "rest",
                    "--method", "POST",
                    "--uri", "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments",
                    "--headers", "Content-Type=application/json",
                    "--body", json.dumps(body)
                ],
                ignore_errors=ignore_patterns
            )
        except Exception as ex:
            # If we still get here, it means a non‐ignored error occurred
            raise RuntimeError(f"[AzureClient] Failed to assign Global Administrator via Graph: {ex}")

        logger.info(f"[AzureClient] Successfully added SP {sp_object_id} as Global Administrator (or it already existed).")

    @staticmethod
    def assign_rbac(sp_object_id: str, project: str) -> None:
        """
        Assigns appropriate RBAC roles (e.g., Contributor) to the given Service Principal at subscription scope.

        Args:
            sp_object_id (str): The Service Principal’s objectId.
            project (str): The project namespace.

        Raises:
            RuntimeError: If role assignment fails.
        """
        subscription_id = mc.cache.get(project, "AZURE_SUBSCRIPTION_ID", recall=AzureSubscription.get(project))
        scope = f"/subscriptions/{subscription_id}"
        role = "Contributor"  # Modify this if assigning different roles

        logger.info(f"[AzureClient] Assigning RBAC role '{role}' to SP {sp_object_id} at scope {scope}")

        ignore_patterns = {
            "roleAssignmentExists": [
                "already exists", "Principal", "already has role", "conflict"
            ]
        }

        try:
            run_az(
                [
                    "az", "role", "assignment", "create",
                    "--assignee", sp_object_id,
                    "--role", role,
                    "--scope", scope
                ],

                ignore_errors=ignore_patterns
            )
        except Exception as ex:
            raise RuntimeError(f"[AzureClient] Failed to assign RBAC role '{role}': {ex}")

        logger.info(f"[AzureClient] ✅ Assigned RBAC role '{role}' to SP {sp_object_id}")


    @staticmethod
    def secret(project: str) -> str:
        """
        Generate a one-time temporary client secret for the AAD app corresponding to `project`
        and cache it in mc.cache.temp under "<project>.client_secret". Returns the secret value.

        Args:
            project (str): The project namespace.

        Returns:
            str: The newly generated client secret.

        Variables:
            app (dict): The AAD application dictionary derived from run_az(az ad app show).
            app_id (str): The "appId" of the AAD application.
            result (dict): The result of run_az(az ad app credential reset ...).
            client_secret (str): The "password" field from result, the actual secret.
        """
        # 1. Check cache for existing app_id
        cached_app_id: Optional[str] = mc.cache.get(project, "app_id")
        if not cached_app_id:
            raise RuntimeError(
                f"[AzureClient] Cannot generate secret; 'app_id' not found in cache for '{project}'."
            )

        # 2. Fetch app to confirm it still exists and resolve correct ID
        try:
            app: Dict[str, Any] = run_az([
                "az", "ad", "app", "show",
                "--id", cached_app_id
            ])
        except Exception as ex:
            raise RuntimeError(
                f"[AzureClient] Failed to fetch AAD app with appId={cached_app_id}: {ex}"
            )

        app_id: Optional[str] = app.get("appId") or app.get("app_id")
        if not app_id:
            raise RuntimeError(f"[AzureClient] Fetched AAD app lacked 'appId' for '{project}'.")

        logger.info(f"[AzureClient] Generating temporary client secret for appId={app_id}")

        # 3. Reset credentials (append secret)
        try:
            result: Dict[str, Any] = run_az([
                "az", "ad", "app", "credential", "reset",
                "--id", app_id,
                "--append",
                "--display-name", f"{project}-temp-secret"
            ])
        except Exception as ex:
            raise RuntimeError(f"[AzureClient] Failed to create client secret: {ex}")

        client_secret: Optional[str] = result.get("password")
        if not client_secret or len(client_secret.strip()) < 5:
            raise RuntimeError(
                f"[AzureClient] Secret generation succeeded but 'password' field was invalid: {result}"
            )

        # 4. Cache the secret temporarily in memory
        mc.cache.temp_set(project, "client_secret", client_secret)
        logger.info(f"[AzureClient] 🔐 Temporary client secret stored in memory for '{project}'")

        return client_secret

