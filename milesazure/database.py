import logging
import time

from typing import Optional, Dict, Any
import subprocess

from milesazure.run import run_az
from milesazure.tenant import AzureSubscription, AzureResourceGroup
from milesazure.vault import Passwords, Secrets  # for admin password retrieval
import context.milescontext as mc

logger = logging.getLogger(__name__)


class DatabaseSetup:
    """
    Handles provisioning and connection setup for Azure Database for PostgreSQL,
    using AzureIDs.get(...) and run_az(...) for all CLI interactions, with proper
    ignore_errors integration to avoid nuking when the server doesn’t exist.
    """

    @staticmethod
    def ensure_postgres_ready(project: str = None) -> Dict[str, Any]:
        """
        Ensure a PostgreSQL flexible server exists and is reachable.

        Returns:
            dict: {
                "DB_SERVER_NAME": str,
                "DB_FQDN": str,
                "DB_LOCATION": str,
                "DB_ID": str,
                "admin_login": str
            }
        """
        project = project or mc.env.get("selected_project_name")
        if not project:
            msg = "[DatabaseSetup] ❌ No project specified or selected in environment."
            logger.error(msg)
            raise RuntimeError(msg)

        try:
            resource_group = mc.cache.get(project,"RESOURCE_GROUP", AzureResourceGroup.get(project))
            db_name = f"{project}-db"
        except RuntimeError as e:
            logger.error(f"[DatabaseSetup] Failed to resolve AzureIDs: {e}")
            raise

        existing_meta = DatabaseSetup.get_postgresql_metadata(project)
        if existing_meta and existing_meta.get("DB_FQDN"):
            logger.info(f"[DatabaseSetup] ✅ PostgreSQL already exists: {existing_meta['DB_FQDN']}")
            return {**existing_meta, "admin_login": existing_meta.get("admin_login", "adminuser")}

        logger.warning(f"[DatabaseSetup] ⚠️ PostgreSQL not found. Creating '{db_name}' in '{resource_group}'")
        return DatabaseSetup.create_postgres(project)

    @staticmethod
    def create_postgres(project: str) -> Dict[str, Any]:
        """
        Create a PostgreSQL flexible server with secure defaults and cache its metadata.

        Returns:
            dict: {
                "DB_SERVER_NAME": str,
                "DB_FQDN": str,
                "DB_LOCATION": str,
                "DB_ID": str,
                "admin_login": str
            }
        """
        db_name = f"{project}-db"
        resource_group = mc.cache.get(project,"RESOURCE_GROUP", AzureResourceGroup.get(project))
        region = mc.cache.get("AZURE_REGION", project) or "eastus"
        admin_user = "adminuser"
        admin_pass = Secrets.get(project, f"{db_name}_DB_PASSWORD")

        logger.info(f"[DatabaseSetup] 🚀 Creating Azure PostgreSQL server: {db_name}")
        run_az(
            [
                "az", "postgres", "flexible-server", "create",
                "--name", db_name,
                "--resource-group", resource_group,
                "--location", region,
                "--admin-user", admin_user,
                "--admin-password", admin_pass,
                "--sku-name", "Standard_B1ms",
                "--storage-size", "32",
                "--yes"
            ],
            capture_output=True
        )

        # Poll until server is ready (up to ~50 seconds)
        for _ in range(10):
            meta = DatabaseSetup.get_postgresql_metadata(project)
            if meta and meta.get("DB_FQDN"):
                logger.info(f"[DatabaseSetup] ✅ PostgreSQL server created: {meta['DB_FQDN']}")
                return {**meta, "admin_login": admin_user}
            time.sleep(5)

        # Final attempt
        meta = DatabaseSetup.get_postgresql_metadata(project) or {}
        if not meta.get("DB_FQDN"):
            msg = "[DatabaseSetup] ❌ Failed to retrieve PostgreSQL metadata after creation."
            logger.error(msg)
            raise RuntimeError(msg)

        logger.info(f"[DatabaseSetup] ✅ PostgreSQL server created: {meta['DB_FQDN']}")
        return {**meta, "admin_login": admin_user}

    @staticmethod
    def get_postgresql_metadata(project: str) -> Optional[Dict[str, str]]:
        """
        Fetch existing PostgreSQL flexible server metadata via Azure CLI and cache it.

        Returns:
            dict: {
                "DB_SERVER_NAME": str,
                "DB_FQDN": str,
                "DB_LOCATION": str,
                "DB_ID": str
            }
            or None if the server does not exist.
        """
        try:
            db_name = f"{project}-db"
            resource_group = mc.cache.get("RESOURCE_GROUP", project, AzureResourceGroup.get(project))
        except RuntimeError as e:
            logger.error(f"[DatabaseSetup] Failed to resolve AzureIDs for metadata: {e}")
            return None

        try:
            result = run_az(
                [
                    "az", "postgres", "flexible-server", "show",
                    "--name", db_name,
                    "--resource-group", resource_group,
                    "--query", "{location: location, fqdn: fullyQualifiedDomainName, id: id}"
                ],
                capture_output=True,
                ignore_errors={"not_found": ["was not found", "does not exist", "resourcenotfound"]}
            )
            # If server doesn't exist, run_az returns {}
            if not result or not isinstance(result, dict):
                return None

            location = result.get("location", "")
            fqdn = result.get("fqdn", "")
            server_id = result.get("id", "")

            if not fqdn:
                return None

            # Cache metadata
            mc.cache.set(project, "DB_SERVER_NAME", str(db_name))
            mc.cache.set(project, "DB_FQDN", str(fqdn))
            mc.cache.set(project, "DB_LOCATION", str(location))
            mc.cache.set(project, "DB_ID", str(server_id))

            return {
                "DB_SERVER_NAME": db_name,
                "DB_FQDN": fqdn,
                "DB_LOCATION": location,
                "DB_ID": server_id,
                "DB_ADMIN_USER": "adminuser"
            }
        except subprocess.CalledProcessError as e:
            # Even with ignore_errors, we guard in case unexpected errors slip through
            logger.warning(f"[DatabaseSetup] CLI error retrieving PostgreSQL metadata: {e.stderr or e}")
            return None
        except Exception as e:
            logger.error(f"[DatabaseSetup] Unexpected error retrieving PostgreSQL metadata: {e}")
            return None

    @staticmethod
    def get_connection_string(project: str) -> str:
        """
        Build a PostgreSQL connection string using cached metadata and admin credentials.

        Returns:
            str: Connection string in the format:
                 "postgresql://<admin_user>:<password>@<fqdn>:5432/<db_name>?sslmode=require"
        """
        meta = DatabaseSetup.get_postgresql_metadata(project)
        if not meta:
            raise RuntimeError(f"[DatabaseSetup] Cannot build connection string; metadata missing for '{project}'")

        db_name = meta["DB_SERVER_NAME"]
        fqdn = meta["DB_FQDN"]
        admin_user = "adminuser"
        admin_pass = Passwords.get(f"{db_name}.PASSWORD", project)

        conn = f"postgresql://{admin_user}:{admin_pass}@{fqdn}:5432/{db_name}?sslmode=require"
        logger.debug(f"[DatabaseSetup] Built connection string for '{project}': {conn}")
        return conn
