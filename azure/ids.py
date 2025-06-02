from typing import Dict, Optional
from azure.tenant import AzureUser
from azure.client import AzureClient

class AzureIDs:
    """
    Lightweight wrapper for resolving Azure identity values from the validated AzureUser context.
    """

    @staticmethod
    def get(key: str, project: str, required: bool = True) -> Optional[str]:
        user_ctx = AzureUser.get(project)
        app_ctx = AzureClient.get(project)  # Contains client_id

        if not user_ctx or app_ctx:
            raise RuntimeError("[AzureIDs] Could not retrieve user or app context!")

        mapping = {
            "AZURE_TENANT_ID": user_ctx.get("tenant_id"),
            "AZURE_SUBSCRIPTION_ID": user_ctx.get("subscription_id"),
            "RESOURCE_GROUP": user_ctx.get("resource_group"),
            "AZURE_REGION": user_ctx.get("region"),
            "AZURE_CLIENT_ID": app_ctx.get("appId"),
            "AZURE_CLIENT_SECRET": AzureClient.secret(project),  # or app_ctx.get("client_secret") if cached
        }

        val = mapping.get(key)

        if val is None and required:
            raise RuntimeError(f"[AzureIDs] Missing required value for key '{key}' in project '{project}'")

        return val

    @staticmethod
    def validate_all(project: str) -> Dict[str, str]:
        print(f"[AzureIDs] Validating all required identity values for project '{project}'")
        return {
            key: AzureIDs.get(key, project=project)
            for key in AzureIDs.REQUIRED_KEYS
        }

    REQUIRED_KEYS = {
        "AZURE_TENANT_ID": "Tenant ID",
        "AZURE_SUBSCRIPTION_ID": "Subscription ID",
        "AZURE_CLIENT_ID": "Client ID",
        "AZURE_CLIENT_SECRET": "Client Secret",
        "RESOURCE_GROUP": "Azure Resource Group",
        "AZURE_REGION": "Azure Region",
        "DB_NAME": "Database Name"  # Can pull from bm.putil.db_name if needed
    }
