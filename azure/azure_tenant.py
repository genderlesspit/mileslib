import time

from backend_methods.milesrequests import Requests
from context import milescontext as mc


class AzureTenant:
    """
    Manages Azure Tenant ID initialization, validation, and retrieval.

    Uses project-scoped keys: <project>.AZURE_TENANT_ID
    """

    @staticmethod
    def init(project: str) -> str:
        """
        Prompts the user for a valid Azure Tenant ID, validates, and stores it.

        Args:
            project (str, optional): Project name for scoping. Defaults to selected project.

        Returns:
            str: Validated and stored tenant ID.
        """
        key = f"{project}.AZURE_TENANT_ID"

        print(f"[AzureTenant] No tenant ID found for project: {project}")
        AzureTenant.help()

        time.sleep(1)
        tenant_id = input("Enter your Azure Tenant ID: ").strip()
        AzureTenant.validate(tenant_id)

        cfg_data = {
            "aad": {
                "AZURE_TENANT_ID": f"{tenant_id}"
            }
        }
        project_root = mc.env.get(f"{project}.root")
        cfg_root = mc.env.get(f"{project}.config_dir")
        mc.env.write(key, tenant_id, replace_existing=True)
        mc.cfg.write(project_root, set=cfg_data)
        print(f"[AzureTenant] Tenant ID set for project '{project}'")
        return tenant_id

    @staticmethod
    def get(project: str) -> str:
        """
        Retrieves the tenant ID for a project, prompting if missing.

        Args:
            project (str, optional): Project scope for env key. Defaults to selected project.

        Returns:
            str: Validated tenant ID.
        """
        key = f"{project}.AZURE_TENANT_ID"

        tenant_id = mc.env.get(key, required=False)
        if not tenant_id:
            return AzureTenant.init(project)

        AzureTenant.validate(tenant_id)
        return tenant_id

    @staticmethod
    def validate(tenant_id: str) -> bool:
        """
        Validates the given tenant ID by checking OpenID metadata.

        Args:
            tenant_id (str): The Azure AD tenant ID to validate.

        Returns:
            bool: True if valid, otherwise raises an error.
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

        Excludes CLI methods that require a tenant ID.
        """
        print("[🔧 How to Find Your Azure Tenant ID]")
        print("─────────────────────────────────────")
        print("📍 Azure Portal (recommended):")
        print("  1. Go to: https://portal.azure.com/")
        print("  2. Select 'Azure Active Directory' from the sidebar.")
        print("  3. Your Tenant ID is listed on the Overview page.")
        print("🧠 Tip: It looks like a UUID (e.g. 72f988bf-86f1-41af-91ab-2d7cd011db47).")
        print("─────────────────────────────────────")
