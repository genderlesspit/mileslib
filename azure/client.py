import json
import logging
from typing import Dict, Optional

from azure import tenant  # tenant.user, tenant.tenant_id, tenant.subscription_id
from azure.run import run_az
from context import milescontext as mc  # mc.cache is the Cache instance

logger = logging.getLogger(__name__)


class AzureClient:
    """Manages Azure App Registration and SP provisioning with Global Admin role assignment."""

    GLOBAL_ADMIN_ROLE_DEFINITION_ID = "62e90394-69f5-4237-9190-012177145e10"
    DIRECTORY_SCOPE = "/"

    @staticmethod
    def verify_app(project: str, display_name: str, cached_app_id: str) -> Dict:
        try:
            app = run_az(["az", "ad", "app", "show", "--id", cached_app_id])
            logger.info(f"[AzureClient] Verified existing app: appId={cached_app_id}")
            return app
        except RuntimeError:
            logger.warning(f"[AzureClient] Cached app_id '{cached_app_id}' not found. Searching by name...")

        filter_str = f"displayName eq \\\"{display_name}\\\""
        apps = run_az(["az", "ad", "app", "list", "--filter", filter_str])
        if isinstance(apps, list) and apps:
            app = apps[0]
            app_id = app.get("appId")
            if app_id:
                logger.info(f"[AzureClient] Found existing app by name: appId={app_id}")
                mc.cache.set(project, "app_id", app_id, include_in_cfg=project)
                return app
        return {}

    @staticmethod
    def create_app(project: str, display_name: str) -> str:
        logger.info(f"[AzureClient] Creating new AAD app: '{display_name}'")
        created = run_az(["az", "ad", "app", "create", "--display-name", display_name])
        app_id = created.get("appId")
        if not app_id:
            raise RuntimeError(f"[AzureClient] Failed to create AAD app '{display_name}'")
        mc.cache.set(project, "app_id", app_id, include_in_cfg=project)
        logger.info(f"[AzureClient] Created AAD app: appId={app_id}")
        return app_id

    @staticmethod
    def get(project: str) -> Dict:
        user_context = tenant.user(project)
        username = user_context.get("user", {}).get("name", "<unknown>")
        logger.info(f"[AzureClient] Logged-in user: {username}")

        t_id = mc.cache.get(project, "tenant_id", recall=lambda: tenant.tenant_id(project))
        s_id = mc.cache.get(project, "subscription_id", recall=lambda: tenant.subscription_id(project))
        logger.info(f"[AzureClient] Using tenant_id={t_id}, subscription_id={s_id}")

        full_display_name = f"{project}-app"
        cached_app_id = mc.cache.get(project, "app_id")
        if cached_app_id:
            app = AzureClient.verify_app(project, full_display_name, cached_app_id)
            app_id = app.get("appId") or app.get("app_id")
            if not app:
                app_id = AzureClient.create_app(project, full_display_name)
                app = run_az(["az", "ad", "app", "show", "--id", app_id])
        else:
            app_id = AzureClient.create_app(project, full_display_name)
            app = run_az(["az", "ad", "app", "show", "--id", app_id])

        if not app_id:
            raise RuntimeError("[AzureClient] Failed to retrieve appId from AAD response.")
        sp_object_id = AzureClient.ensure_service_principal(app_id)
        AzureClient.assign_global_admin(sp_object_id, project)

        logger.info(f"[AzureClient] Application setup complete: appId={app_id}, spObjectId={sp_object_id}")
        return app

    @staticmethod
    def verify_sp(app_id: str) -> Optional[str]:
        if not app_id or not isinstance(app_id, str):
            raise ValueError("[AzureClient.verify_sp] Invalid app_id provided.")

        logger.info(f"[AzureClient] Checking for existing service principal for appId={app_id}")
        try:
            result = run_az(["az", "ad", "sp", "show", "--id", app_id])
            sp_id = result.get("id")
            if sp_id:
                logger.info(f"[AzureClient] ✅ SP found: object_id={sp_id}")
                return sp_id
            logger.warning(f"[AzureClient] SP lookup returned no 'id': {result}")
            return None
        except RuntimeError as e:
            if "does not exist" in str(e).lower() or "exit status 3" in str(e).lower():
                logger.info(f"[AzureClient] SP not found for appId={app_id} (expected).")
                return None
            logger.error(f"[AzureClient] Error checking SP: {e}")
            raise

    @staticmethod
    def create_sp(project: str, app_id: str) -> str:
        logger.info(f"[AzureClient] Creating new SP for appId={app_id}")
        sp = run_az(["az", "ad", "sp", "create", "--id", app_id])
        object_id = sp.get("objectId") or sp.get("id")
        if not object_id:
            raise RuntimeError(f"[AzureClient] Failed to create SP for appId '{app_id}'")
        mc.cache.set(project, "sp_object_id", object_id, include_in_cfg=project)
        logger.info(f"[AzureClient] Created new SP: objectId={object_id}")
        return object_id

    @staticmethod
    def ensure_service_principal(app_id: str) -> str:
        try:
            sp = run_az(["az", "ad", "sp", "show", "--id", app_id])
            return sp.get("objectId") or sp.get("id")
        except RuntimeError as e:
            logger.warning(f"[AzureClient] SP missing for appId={app_id}, creating new one...")
            sp = run_az(["az", "ad", "sp", "create", "--id", app_id])
            return sp.get("objectId") or sp.get("id")

    @staticmethod
    def assign_global_admin(object_id: str, project: str) -> None:
        """
        Assign the Global Administrator role to the given SP object ID.
        If the role is already assigned, swallow the 400 “conflicting object” and continue.
        """
        import json
        from azure.run import run_az

        print(f"[AzureClient] Assigning Global Admin role to SP objectId={object_id}")
        body = {
            "principalId": object_id,
            "roleDefinitionId": AzureClient.GLOBAL_ADMIN_ROLE_DEFINITION_ID,
            "directoryScopeId": AzureClient.DIRECTORY_SCOPE
        }

        try:
            # We explicitly capture output here so we can read any error message.
            run_az(
                [
                    "az", "rest",
                    "--method", "POST",
                    "--uri", "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments",
                    "--body", json.dumps(body)
                ],
                capture_output=True  # ← capture so we can read any error message
            )
            print(f"[AzureClient] ✅ Global Admin role assigned to {object_id}")
            mc.cache.set(project, "admin_assigned", "true", include_in_cfg=project)

        except RuntimeError as ex:
            # If Graph returns 400 with “conflicting object…”, that means “already assigned.” Just continue.
            msg = str(ex).lower()
            if "conflicting object" in msg or "already exists" in msg:
                print(f"[AzureClient] ℹ️ Global Admin role was already assigned to {object_id}. Continuing.")
                mc.cache.set(project, "admin_assigned", "true", include_in_cfg=project)
                return

            # For any other error, re‐raise as before.
            raise RuntimeError(f"[AzureClient] Failed to assign Global Admin role: {ex}")

    @staticmethod
    def check_user_is_global_admin(project: str) -> bool:
        logger.info(f"[AzureClient] Checking if current user is Global Admin for project='{project}'")
        user_ctx = tenant.user(project)
        user_id = user_ctx.get("user", {}).get("id") or user_ctx.get("user", {}).get("objectId")
        if not user_id:
            logger.warning("[AzureClient] Missing user object ID.")
            return False

        try:
            assignments = run_az(["az", "role", "assignment", "list", "--assignee", user_id])
            for a in assignments or []:
                if a.get("roleDefinitionName") == "Global Administrator":
                    logger.info(f"[AzureClient] ✅ User {user_id} is Global Admin.")
                    return True
        except RuntimeError as e:
            logger.error(f"[AzureClient] Failed to retrieve role assignments: {e}")
            return False

        logger.info(f"[AzureClient] ❌ User {user_id} is NOT Global Admin.")
        return False

    @staticmethod
    def secret(project: str) -> str:
        app = AzureClient.get(project)
        app_id = app.get("appId")
        if not app_id:
            raise RuntimeError(f"[AzureClient] Missing appId for project '{project}'")

        logger.info(f"[AzureClient] Generating temporary client secret for appId={app_id}")
        try:
            result = run_az([
                "az", "ad", "app", "credential", "reset",
                "--id", app_id,
                "--append",
                "--display-name", f"{project}-temp-secret"
            ])
        except Exception as ex:
            raise RuntimeError(f"[AzureClient] Failed to create client secret: {ex}")

        client_secret = result.get("password")
        if not client_secret:
            raise RuntimeError("[AzureClient] Secret generation succeeded but 'password' missing.")

        mc.cache.temp_set(project, "client_secret", client_secret)
        logger.info(f"[AzureClient] 🔐 Temporary client secret stored in memory for '{project}'")
        return client_secret
