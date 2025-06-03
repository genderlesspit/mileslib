import logging
from typing import Dict, Any, Union, Optional

import util.sanitization
from milesazure.ids import AzureServicePrincipal, AzureIDs
from milesazure.run import run_az

from milesazure.vault import (
    store_secret,
    retrieve_secret,
    get_or_generate_password,
)

logger = logging.getLogger(__name__)

class Provision:
    """
    Provision all necessary Azure resources for a Django web app under a given project.
    Uses AzureServicePrincipal.get_context(project) to authenticate and set subscription.
    """

    class ResourceGroup:
        """
        Ensure the Azure Resource Group exists.
        """

        @staticmethod
        def create(project: str) -> str:
            """
            Create or validate the resource group for `project`.

            Variables:
                sub_id: str
                rg_name: str
                region: str

            Logic:
                1. Validate `project`.
                2. Fetch subscription_id, resource_group name, and region via AzureIDs.get.
                3. Call run_az to create the resource group (idempotent).
                4. Return the resource group name.
            """
            if not isinstance(project, str) or not project.strip():
                raise TypeError("Provision.ResourceGroup.create: 'project' must be a non-empty string")

            try:
                sub_id: str = AzureIDs.get("AZURE_SUBSCRIPTION_ID", project, required=True)
                rg_name: str = AzureIDs.get("RESOURCE_GROUP", project, required=True)
                region: str = AzureIDs.get("AZURE_REGION", project, required=True)
            except Exception as ex:
                raise RuntimeError(f"[Provision.ResourceGroup] Failed to retrieve AzureIDs for '{project}': {ex}")

            logger.debug(
                "[Provision.ResourceGroup] Creating or validating RG '%s' in subscription '%s', location '%s'.",
                rg_name, sub_id, region
            )

            try:
                run_az(
                    [
                        "az", "group", "create",
                        "--name", rg_name,
                        "--location", region,
                        "--subscription", sub_id,
                        "--output", "json"
                    ],
                    capture_output=True
                )
                logger.info("[Provision.ResourceGroup] Resource Group '%s' is ready.", rg_name)
            except Exception as ex:
                raise RuntimeError(f"[Provision.ResourceGroup] Failed to create/validate RG '{rg_name}': {ex}")

            return rg_name

    class PostgreSQL:
        """
        Create Azure Database for PostgreSQL server and default database for Django.
        """

        @staticmethod
        def create(
            project: str,
            admin_user: str,
            admin_password: str
        ) -> Dict[str, str]:
            """
            Create or validate a PostgreSQL server for `project`.

            Variables:
                sub_id: str
                rg_name: str
                region: str
                server_name: str
                db_name: str
                sku: str

            Logic:
                1. Validate parameters.
                2. Fetch subscription_id, resource_group, and region.
                3. Determine server_name = f"{project}-psql".
                   db_name = f"{project}db".
                   sku = "B_Gen5_1" (Basic, Gen5, tier 1).
                4. Call run_az to create PostgreSQL server (idempotent).
                5. Call run_az to configure firewall rule to allow Azure services.
                6. Call run_az to create default database.
                7. Return a dict with:
                   {
                     "server_name": <server_name>,
                     "fully_qualified_domain_name": <fqdn>,
                     "database_name": <db_name>
                   }
            """
            for arg_name, arg in (("project", project), ("admin_user", admin_user), ("admin_password", admin_password)):
                if not isinstance(arg, str) or not arg.strip():
                    raise TypeError(f"Provision.PostgreSQL.create: '{arg_name}' must be a non-empty string")

            try:
                sub_id: str = AzureIDs.get("AZURE_SUBSCRIPTION_ID", project, required=True)
                rg_name: str = AzureIDs.get("RESOURCE_GROUP", project, required=True)
                region: str = AzureIDs.get("AZURE_REGION", project, required=True)
            except Exception as ex:
                raise RuntimeError(f"[Provision.PostgreSQL] Failed to retrieve AzureIDs for '{project}': {ex}")

            server_name: str = f"{project}-psql"
            db_name: str = f"{project}db"
            sku: str = "B_Gen5_1"

            logger.debug(
                "[Provision.PostgreSQL] Creating/validating PostgreSQL server '%s' in RG '%s' (region='%s').",
                server_name, rg_name, region
            )

            try:
                run_az(
                    [
                        "az", "postgres", "server", "create",
                        "--resource-group", rg_name,
                        "--name", server_name,
                        "--location", region,
                        "--admin-user", admin_user,
                        "--admin-password", admin_password,
                        "--sku-name", sku,
                        "--version", "12",
                        "--subscription", sub_id,
                        "--output", "json"
                    ],
                    capture_output=True
                )
                logger.info("[Provision.PostgreSQL] PostgreSQL server '%s' is ready.", server_name)
            except Exception as ex:
                stderr = str(ex).lower()
                if "already exists" in stderr:
                    logger.info("[Provision.PostgreSQL] Server '%s' already exists; skipping creation.", server_name)
                else:
                    raise RuntimeError(f"[Provision.PostgreSQL] Failed to create server '{server_name}': {ex}")

            # Configure firewall rule to allow Azure services
            try:
                run_az(
                    [
                        "az", "postgres", "server", "firewall-rule", "create",
                        "--resource-group", rg_name,
                        "--server-name", server_name,
                        "--name", "allow_azure_ips",
                        "--start-ip-address", "0.0.0.0",
                        "--end-ip-address", "0.0.0.0",
                        "--subscription", sub_id,
                        "--output", "json"
                    ],
                    capture_output=True
                )
                logger.debug("[Provision.PostgreSQL] Firewall rule 'allow_azure_ips' configured for server '%s'.", server_name)
            except Exception as ex:
                stderr = str(ex).lower()
                if "already exists" in stderr:
                    logger.debug("[Provision.PostgreSQL] Firewall rule already exists; skipping.")
                else:
                    raise RuntimeError(f"[Provision.PostgreSQL] Failed to set firewall rule on '{server_name}': {ex}")

            # Create the default database
            try:
                run_az(
                    [
                        "az", "postgres", "db", "create",
                        "--resource-group", rg_name,
                        "--server-name", server_name,
                        "--name", db_name,
                        "--subscription", sub_id,
                        "--output", "json"
                    ],
                    capture_output=True
                )
                logger.info("[Provision.PostgreSQL] Database '%s' created on server '%s'.", db_name, server_name)
            except Exception as ex:
                stderr = str(ex).lower()
                if "already exists" in stderr:
                    logger.info("[Provision.PostgreSQL] Database '%s' already exists; skipping.", db_name)
                else:
                    raise RuntimeError(f"[Provision.PostgreSQL] Failed to create database '{db_name}': {ex}")

            # Fetch fully qualified domain name
            try:
                server_info: str = run_az(
                    [
                        "az", "postgres", "server", "show",
                        "--resource-group", rg_name,
                        "--name", server_name,
                        "--query", "fullyQualifiedDomainName",
                        "--output", "tsv"
                    ],
                    capture_output=True
                )
                fqdn: str = server_info.strip()
            except Exception as ex:
                raise RuntimeError(f"[Provision.PostgreSQL] Failed to fetch FQDN for '{server_name}': {ex}")

            return {
                "server_name": server_name,
                "fully_qualified_domain_name": fqdn,
                "database_name": db_name
            }

    class AppService:
        """
        Create App Service Plan and Web App for Django.
        """

        @staticmethod
        def create_plan(project: str) -> str:
            """
            Create or validate an App Service Plan for `project`.

            Variables:
                sub_id: str
                rg_name: str
                plan_name: str
                sku: str

            Logic:
                1. Validate `project`.
                2. Fetch subscription_id and resource_group via AzureIDs.get.
                3. Define plan_name = f"{project}-plan", sku = "B1".
                4. Call run_az to create the plan (Linux, idempotent).
                5. Return the plan_name.
            """
            if not isinstance(project, str) or not project.strip():
                raise TypeError("Provision.AppService.create_plan: 'project' must be a non-empty string")

            try:
                sub_id: str = AzureIDs.get("AZURE_SUBSCRIPTION_ID", project, required=True)
                rg_name: str = AzureIDs.get("RESOURCE_GROUP", project, required=True)
            except Exception as ex:
                raise RuntimeError(f"[Provision.AppService] Failed to retrieve AzureIDs for '{project}': {ex}")

            plan_name: str = f"{project}-plan"
            sku: str = "B1"

            logger.debug(
                "[Provision.AppService] Creating/validating App Service Plan '%s' in RG '%s'.",
                plan_name, rg_name
            )

            try:
                run_az(
                    [
                        "az", "appservice", "plan", "create",
                        "--name", plan_name,
                        "--resource-group", rg_name,
                        "--sku", sku,
                        "--is-linux",
                        "--subscription", sub_id,
                        "--output", "json"
                    ],
                    capture_output=True
                )
                logger.info("[Provision.AppService] App Service Plan '%s' is ready.", plan_name)
            except Exception as ex:
                stderr = str(ex).lower()
                if "already exists" in stderr:
                    logger.info("[Provision.AppService] Plan '%s' already exists; skipping.", plan_name)
                else:
                    raise RuntimeError(f"[Provision.AppService] Failed to create plan '{plan_name}': {ex}")

            return plan_name

        @staticmethod
        def create_webapp(project: str) -> str:
            """
            Create or validate a Web App for Django under `project`.

            Variables:
                sub_id: str
                rg_name: str
                plan_name: str
                webapp_name: str
                runtime: str

            Logic:
                1. Validate `project`.
                2. Fetch subscription_id, resource_group via AzureIDs.get.
                3. Get plan_name by calling create_plan(project).
                4. Define webapp_name = f"{project}-webapp", runtime = "PYTHON|3.8".
                5. Call run_az to create the web app (idempotent).
                6. Return the webapp_name.
            """
            if not isinstance(project, str) or not project.strip():
                raise TypeError("Provision.AppService.create_webapp: 'project' must be a non-empty string")

            try:
                sub_id: str = AzureIDs.get("AZURE_SUBSCRIPTION_ID", project, required=True)
                rg_name: str = AzureIDs.get("RESOURCE_GROUP", project, required=True)
            except Exception as ex:
                raise RuntimeError(f"[Provision.AppService] Failed to retrieve AzureIDs for '{project}': {ex}")

            plan_name: str = Provision.AppService.create_plan(project)
            webapp_name: str = f"{project}-webapp"
            runtime: str = "PYTHON|3.8"

            logger.debug(
                "[Provision.AppService] Creating/validating Web App '%s' under plan '%s'.",
                webapp_name, plan_name
            )

            try:
                run_az(
                    [
                        "az", "webapp", "create",
                        "--resource-group", rg_name,
                        "--plan", plan_name,
                        "--name", webapp_name,
                        "--runtime", runtime,
                        "--subscription", sub_id,
                        "--output", "json"
                    ],
                    capture_output=True
                )
                logger.info("[Provision.AppService] Web App '%s' is ready.", webapp_name)
            except Exception as ex:
                stderr = str(ex).lower()
                if "already exists" in stderr:
                    logger.info("[Provision.AppService] Web App '%s' already exists; skipping.", webapp_name)
                else:
                    raise RuntimeError(f"[Provision.AppService] Failed to create Web App '{webapp_name}': {ex}")

            return webapp_name

        @staticmethod
        def configure_connection_string(
            project: str,
            webapp_name: str,
            conn_str_name: str,
            conn_str_value: str
        ) -> None:
            """
            Configure a connection string for `webapp_name` in App Service.

            Variables:
                sub_id: str
                rg_name: str

            Logic:
                1. Validate parameters.
                2. Fetch subscription_id, resource_group via AzureIDs.get.
                3. Call run_az to set the connection string:
                     az webapp config connection-string set
                         --resource-group <rg_name>
                         --name <webapp_name>
                         --settings <conn_str_name>=<conn_str_value>
                         --connection-string-type PostgreSQL
                4. Return None.
            """
            if not all(isinstance(x, str) and x.strip() for x in (project, webapp_name, conn_str_name, conn_str_value)):
                raise TypeError("Provision.AppService.configure_connection_string: all parameters must be non-empty strings")

            try:
                sub_id: str = AzureIDs.get("AZURE_SUBSCRIPTION_ID", project, required=True)
                rg_name: str = AzureIDs.get("RESOURCE_GROUP", project, required=True)
            except Exception as ex:
                raise RuntimeError(f"[Provision.AppService] Failed to retrieve AzureIDs for '{project}': {ex}")

            logger.debug(
                "[Provision.AppService] Configuring connection string '%s' for Web App '%s'.",
                conn_str_name, webapp_name
            )

            try:
                run_az(
                    [
                        "az", "webapp", "config", "connection-string", "set",
                        "--resource-group", rg_name,
                        "--name", webapp_name,
                        "--settings", f"{conn_str_name}={conn_str_value}",
                        "--connection-string-type", "PostgreSQL",
                        "--subscription", sub_id,
                        "--output", "json"
                    ],
                    capture_output=True
                )
                logger.info(
                    "[Provision.AppService] Connection string '%s' set on Web App '%s'.",
                    conn_str_name, webapp_name
                )
            except Exception as ex:
                raise RuntimeError(
                    f"[Provision.AppService] Failed to configure connection string on '{webapp_name}': {ex}"
                )

    @staticmethod
    def provision_all(
        project: str,
        db_admin_user: Optional[str] = None,
        db_admin_password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Provision all Azure resources required for a Django web app.

        Logic:
            1. Validate inputs.
            2. Initialize SP context via AzureServicePrincipal.get_context(project).
            3. Create or validate the Resource Group.
            4. Determine or retrieve the DB admin user and password using Key Vault convenience functions.
            5. Create or validate the PostgreSQL server & database.
            6. Build a Django DATABASE_URL connection string.
            7. Create or validate the Web App.
            8. Configure the connection string on the Web App.
            9. Store the connection string in Key Vault.
            10. Return a summary dict of all provisioned resources.
        """
        # 1. Validate inputs
        if not isinstance(project, str) or not project.strip():
            raise TypeError("Provision.provision_all: 'project' must be a non-empty string")

        # 2. Initialize SP context (login + set subscription)
        try:
            AzureServicePrincipal.get_context(project)
            logger.info("[Provision] SP context initialized for project '%s'.", project)
        except Exception as ex:
            raise RuntimeError(f"[Provision] Failed to initialize SP context for '{project}': {ex}")

        # 3. Ensure Resource Group exists
        rg_name: str = Provision.ResourceGroup.create(project)

        # 4. Determine or retrieve DB admin user and password
        #    - If db_admin_user is provided, store it; else generate a default.
        if isinstance(db_admin_user, str) and db_admin_user.strip():
            admin_user = db_admin_user.strip()
        else:
            admin_user = f"{project}_admin"
            store_secret("db_admin_user", admin_user, project)
            logger.info("[Provision] Generated default DB admin user '%s' for project '%s'.", admin_user, project)
            util.sanitization.Sanitization.standard(admin_user)

        #    - For password:
        if isinstance(db_admin_password, str) and db_admin_password.strip():
            admin_password = db_admin_password
            store_secret("db_admin_password", admin_password, project)
            logger.info("[Provision] Stored provided DB admin password for project '%s'.", project)
        else:
            admin_password = get_or_generate_password("db_admin_password", project)
            logger.info("[Provision] Retrieved or generated DB admin password for project '%s'.", project)

        # 5. Create or validate PostgreSQL server & database
        psql_info: Dict[str, str] = Provision.PostgreSQL.create(
            project,
            admin_user,
            admin_password
        )

        # 6. Build connection string: "postgres://<user>:<pass>@<fqdn>:5432/<db_name>"
        fqdn = psql_info["fully_qualified_domain_name"]
        db_name = psql_info["database_name"]
        conn_str = f"postgres://{admin_user}:{admin_password}@{fqdn}:5432/{db_name}"
        logger.debug("[Provision] Built connection string for project '%s': %s", project, conn_str)

        # 7. Create or validate Web App
        webapp_name: str = Provision.AppService.create_webapp(project)

        # 8. Configure the connection string on the Web App
        Provision.AppService.configure_connection_string(
            project,
            webapp_name,
            conn_str_name="DATABASE_URL",
            conn_str_value=conn_str
        )

        # 9. Store the connection string in Key Vault
        store_secret("DATABASE_URL", conn_str, project)
        logger.info("[Provision] Stored connection string in Key Vault for project '%s'.", project)

        # 10. Return summary of provisioned resources
        result: Dict[str, Any] = {
            "resource_group": rg_name,
            "postgresql_server": psql_info["server_name"],
            "postgresql_fqdn": fqdn,
            "postgresql_database": db_name,
            "webapp": webapp_name,
            "connection_string": conn_str
        }

        logger.info("[Provision] Provisioning completed for project '%s': %s", project, result)
        return result
