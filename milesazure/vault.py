import logging
import secrets
import string
import time

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.keyvault import KeyVaultManagementClient

import context.milescontext as mc
from context.milescontext import cache
from milesazure.client import AzureClient
from milesazure.run import run_az
from milesazure.tenant import AzureSubscription, AzureResourceGroup
from util import sanitization as sanny

logger = logging.getLogger(__name__)


class VaultSetup:
    """
    Handles creation, validation, and retrieval of Azure Key Vaults for a given project context.

    Responsibilities:
    - Resolve Azure IDs (subscription, resource group, region) via milesazure.ids.AzureIDs.get
    - Use run_az to invoke Azure CLI commands for listing, creating, and querying vaults
    - Initialize a Secrets client once the vault is available
    """

    @staticmethod
    def ensure_vault_ready(project: str = None) -> str:
        """
        Ensure a Key Vault exists and can be accessed for the specified project.
        Returns:
            str: The vault URI
        Raises:
            RuntimeError if any required Azure ID is missing or vault creation/lookup fails
        """
        project = project or mc.env.get("selected_project_name")
        if not project:
            msg = "[VaultSetup] ❌ No project specified or selected in environment."
            logger.error(msg)
            raise RuntimeError(msg)

        # Resolve required Azure IDs
        try:
            subscription_id = cache.get("AZURE_SUBSCRIPTION_ID", project, recall=AzureSubscription.get(project))
        except RuntimeError as e:
            logger.error(f"[VaultSetup] Failed to get subscription ID: {e}")
            raise

        # Region is not strictly required; default to "eastus" if missing
        region = cache.get("AZURE_REGION", project) or "eastus"

        # List existing vaults (diagnostic)
        VaultSetup.list_existing_vaults(subscription_id, region)

        # Attempt to fetch an existing vault
        try:
            vault_meta = VaultSetup.get_vault(project)
            logger.info(f"[VaultSetup] ✅ Vault exists: {vault_meta['name']} ({vault_meta['uri']})")
        except Exception as e:
            logger.warning(f"[VaultSetup] ⚠️ Vault not found. Creating new vault: {e}")
            vault_meta = VaultSetup.create_vault(project)

        uri = vault_meta.get("uri")
        if not uri:
            msg = "[VaultSetup] ❌ Vault creation succeeded but URI is missing."
            logger.error(msg)
            raise RuntimeError(msg)

        # Initialize the Secrets client (Key Vault SDK) for the project
        if not Secrets.load_vault(project):
            msg = "[VaultSetup] ❌ Failed to initialize Secrets client after vault creation."
            logger.error(msg)
            raise RuntimeError(msg)

        return uri

    @staticmethod
    def list_existing_vaults(subscription_id: str, region: str = None) -> list:
        """
        Retrieve a list of existing Key Vaults in the subscription (filtered by region if provided).
        Args:
            subscription_id (str): Azure subscription ID
            region (str): Optional Azure region to filter vaults (case-insensitive)
        Returns:
            list: List of vault metadata dicts as returned by 'az keyvault list'
        Raises:
            RuntimeError if subscription_id is missing
        """
        if not subscription_id:
            msg = "[VaultSetup] ❌ subscription_id is required for listing vaults."
            logger.error(msg)
            raise RuntimeError(msg)

        # Use run_az to call: az keyvault list --subscription <subscription_id>
        vaults = run_az(
            ["az", "keyvault", "list", "--subscription", subscription_id],
            capture_output=True
        )
        # run_az returns a parsed JSON list
        if not isinstance(vaults, list):
            msg = "[VaultSetup] ❌ Unexpected response format when listing vaults."
            logger.error(msg)
            raise RuntimeError(msg)

        # Filter by region if provided
        if region:
            vaults = [v for v in vaults if v.get("location", "").lower() == region.lower()]

        logger.info(f"[VaultSetup] 🔍 Found {len(vaults)} vault(s){f' in region={region}' if region else ''}")
        for v in vaults:
            name = v.get("name", "<unknown>")
            loc = v.get("location", "<unknown>")
            logger.debug(f"  - {name} ({loc})")

        return vaults

    @staticmethod
    def ensure_keyvault_provider_registered(subscription_id: str):
        """
        Ensure the Microsoft.KeyVault resource provider is registered under this subscription.
        Args:
            subscription_id (str): Azure subscription ID
        Raises:
            RuntimeError if subscription_id is missing
        """
        if not subscription_id:
            msg = "[VaultSetup] ❌ subscription_id is required for provider registration."
            logger.error(msg)
            raise RuntimeError(msg)

        # Query the provider's registration state
        state = run_az(
            ["az", "provider", "show", "--namespace", "Microsoft.KeyVault", "--subscription", subscription_id,
             "--query", "registrationState"],
            capture_output=True
        )
        # run_az returns a Python value, usually a string for this query
        if not isinstance(state, str):
            msg = "[VaultSetup] ❌ Unexpected response format when checking provider registration."
            logger.error(msg)
            raise RuntimeError(msg)

        if state != "Registered":
            logger.info("[VaultSetup] 🔧 Registering Microsoft.KeyVault provider...")
            run_az(
                ["az", "provider", "register", "--namespace", "Microsoft.KeyVault", "--subscription", subscription_id],
                capture_output=True
            )
            logger.info("[VaultSetup] ⏳ Waiting for provider registration...")
            # Poll until the provider is marked as Registered
            while True:
                check = run_az(
                    ["az", "provider", "show", "--namespace", "Microsoft.KeyVault", "--subscription", subscription_id,
                     "--query", "registrationState"],
                    capture_output=True
                )
                if check == "Registered":
                    break
                time.sleep(2)
            logger.info("[VaultSetup] ✅ Microsoft.KeyVault provider registered.")

    @staticmethod
    def create_vault(project: str) -> dict:
        """
        Create a new Azure Key Vault for the given project.
        Returns:
            dict: { "name": str, "uri": str }
        Raises:
            RuntimeError if any required Azure ID is missing or CLI calls fail
        """
        project = project or mc.env.get("selected_project_name")
        if not project:
            msg = "[VaultSetup] ❌ No project specified or selected in environment."
            logger.error(msg)
            raise RuntimeError(msg)

        # Resolve required Azure IDs
        try:
            subscription_id = cache.get("AZURE_SUBSCRIPTION_ID", project, recall=AzureSubscription.get(project))
            resource_group = cache.get("RESOURCE_GROUP", project, recall=AzureResourceGroup.get(project))
        except RuntimeError as e:
            logger.error(f"[VaultSetup] Failed to resolve AzureIDs: {e}")
            raise

        # Region fallback to "eastus"
        region = cache.get("AZURE_REGION", project, recall="eastus")

        # Ensure the KeyVault provider is registered
        VaultSetup.ensure_keyvault_provider_registered(subscription_id)

        # Determine or generate a vault name
        vault_name = cache.get(project,"VAULT_NAME", recall=f"{project}-vault")

        logger.info(f"[VaultSetup] 🚀 Creating Key Vault: {vault_name} in {resource_group} (region={region})")
        # Create the vault (uses run_az under the hood)
        run_az(
            [
                "az", "keyvault", "create",
                "--name", vault_name,
                "--location", region,
                "--resource-group", resource_group,
                "--enable-rbac-authorization", "true"
            ],
            capture_output=True
        )

        # Retrieve the vault URI via CLI and parse JSON
        uri = run_az(
            [
                "az", "keyvault", "show",
                "--name", vault_name,
                "--resource-group", resource_group,
                "--query", "properties.vaultUri"
            ],
            capture_output=True
        )
        # run_az for a "--query" that returns a string yields that string directly
        if not isinstance(uri, str):
            msg = f"[VaultSetup] ❌ Failed to retrieve URI for newly created vault '{vault_name}'."
            logger.error(msg)
            raise RuntimeError(msg)

        logger.info(f"[VaultSetup] ✅ Vault created: {vault_name} ({uri})")
        mc.cache.set(project, "name", str(vault_name))
        mc.cache.set(project, "location", str(region))
        mc.cache.set(project, "uri", str(uri))

        return {"name": vault_name, "uri": uri}

    @staticmethod
    def get_vault(project: str) -> dict:
        """
        Fetch existing Key Vault metadata using the Azure SDK.
        Returns:
            dict: {
                "name": str,
                "location": str,
                "id": str,
                "uri": str,
                "policies": List[str],
                "enabled_for_template_deployment": bool
            }
        Raises:
            RuntimeError if Azure SDK call fails or required IDs are missing
        """
        project = project or mc.env.get("selected_project_name")
        if not project:
            msg = "[VaultSetup] ❌ No project specified or selected in environment."
            logger.error(msg)
            raise RuntimeError(msg)

        try:
            subscription_id = cache.get("AZURE_SUBSCRIPTION_ID", project, AzureSubscription.get(project))
            resource_group = cache.get("RESOURCE_GROUP", project, recall=AzureResourceGroup.get(project))
            vault_name = f"{project}-vault"
        except RuntimeError as e:
            logger.error(f"[VaultSetup] Failed to resolve AzureIDs or environment: {e}")
            raise

        try:
            credential = DefaultAzureCredential()
            kv_client = KeyVaultManagementClient(credential, subscription_id)
            vault = kv_client.vaults.get(resource_group_name=resource_group, vault_name=vault_name)

            metadata = {
                "VAULT_NAME": vault.name,
                "VAULT_LOCATION": vault.location,
                "VAULT_ID": vault.id,
                "VAULT_URI": vault.properties.vault_uri,
                "VAULT_POLICIES": [p.object_id for p in vault.properties.access_policies],
                "VAULT_ENABLED_FOR_TEMPLATE_DEPLOYMENT": vault.properties.enabled_for_template_deployment,
            }

            for key, val in metadata.items():
                try:
                    mc.cache.set(project, key, str(val))
                except Exception as e:
                    logger.warning(f"[VaultSetup] Failed to cache {key}: {e}")

            return metadata

        except Exception as e:
            msg = f"[VaultSetup] ❌ Failed to retrieve vault '{vault_name}': {e}"
            logger.error(msg)
            raise RuntimeError(msg)

    @staticmethod
    def get_url(project: str) -> str | None:
        """
        Return the Key Vault URI if it exists; otherwise, return None.
        Does not create or modify any vault.
        Args:
            project (str): Project namespace
        Returns:
            str | None: Vault URI or None if not found
        """
        project = project or mc.env.get("selected_project_name")
        if not project:
            logger.debug("[VaultSetup] get_url called without a project; returning None.")
            return None

        try:
            vault_meta = VaultSetup.get_vault(project)
            return vault_meta.get("uri")
        except Exception:
            return None

    @staticmethod
    def get_current_object_id() -> str | None:
        """
        Return the Object ID of the signed-in user or service principal.
        Attempts Graph API first, then falls back to Azure CLI via run_az.
        Returns:
            str | None: Object ID or None if not found
        Raises:
            RuntimeError or RuntimeWarning if resolution fails
        """
        project = mc.env.get("selected_project_name")
        if not project:
            msg = "[VaultSetup] ❌ No project selected in environment for get_current_object_id."
            logger.error(msg)
            raise RuntimeError(msg)

        # 1) Try Graph-based resolution if available
        #try:
            #session = AzureIDs._load_contexts  # this is just to ensure AzureIDs context is loaded
            # If a Graph session method exists, use it (pseudocode):
            # graph_session = bm.GraphInitialization.get_session("global")
            # me_resp = graph_session.get("https://graph.microsoft.com/v1.0/me")
            # if me_resp.status_code == 200:
            #     return me_resp.json().get("id")
        #except Exception:
            #pass

        # 2) Fallback: use Azure CLI to get the service principal's objectId
        try:
            client_id = cache.get("AZURE_CLIENT_ID", project, recall=AzureClient.get(project)["appId"])
            if not client_id:
                msg = "[VaultSetup] AZURE_CLIENT_ID is missing; cannot resolve object ID."
                logger.error(msg)
                raise RuntimeError(msg)

            obj_id = run_az(
                ["az", "ad", "sp", "show", "--id", client_id, "--query", "objectId"],
                capture_output=True
            )
            # run_az for a "--query" returning a string yields that string directly
            if not isinstance(obj_id, str):
                msg = "[VaultSetup] ❌ Azure CLI returned unexpected format for objectId."
                logger.error(msg)
                raise RuntimeError(msg)
            return obj_id
        except Exception as e:
            warning_msg = f"[VaultSetup] Could not resolve objectId via Azure CLI: {e}"
            logger.warning(warning_msg)
            raise RuntimeWarning(warning_msg)


class Secrets:
    """
    Secure secrets manager for retrieving and caching credentials.
    Primary source: Azure Key Vault.
    Fallback: OS environment variables.

    Does not persist secrets to disk under any circumstances.
    """

    _cache = {}
    _client = None

    @staticmethod
    def sanitize(key: str) -> str:
        sanny_key = sanny.purge(key)
        return sanny_key

    @staticmethod
    def _get_credential(project: str):
        """
        Resolve an appropriate Azure credential for accessing the Key Vault.
        Uses ClientSecretCredential if scoped values exist, else falls back to DefaultAzureCredential.
        """
        from azure.identity import DefaultAzureCredential, ClientSecretCredential

        tenant_id = mc.env.get(f"{project}.AZURE_TENANT_ID", required=False)
        client_id = mc.env.get(f"{project}.AZURE_CLIENT_ID", required=False)

        # First try to get secret from cache, then from env
        client_secret = mc.cache.temp_get(project, "client_secret") or mc.env.get(f"{project}.AZURE_CLIENT_SECRET", required=False)

        if tenant_id and client_id and client_secret:
            logger.debug(f"[Secrets] Using ClientSecretCredential for project: {project}")
            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )

        logger.debug(f"[Secrets] Falling back to DefaultAzureCredential for project: {project}")
        return DefaultAzureCredential()


    @staticmethod
    def load_vault(project: str = None):
        """
        Load a Key Vault client for the given project.
        Auto-creates the vault if missing.

        Returns:
            Azure Key Vault SecretClient
        """
        project = project or mc.env.get("selected_project_name")
        if not project:
            raise RuntimeError("[Secrets] No project specified or selected.")

        uri = mc.cache.get(project, "VAULT_URI")
        if not uri:
            logger.warning(f"[Secrets] Vault URI missing in cache. Running ensure_vault_ready...")
            uri = VaultSetup.ensure_vault_ready(project)

        try:
            credential = Secrets._get_credential(project)
            client = SecretClient(vault_url=uri, credential=credential)
            return client
        except Exception as e:
            raise RuntimeError(f"[Secrets] Failed to load Key Vault client: {e}")

    @staticmethod
    def store(name: str, value: str, project: str) -> None:
        """
        Persist the secret to Azure Key Vault.
        This method will overwrite any existing secret in Key Vault.

        Args:
            name (str): The name of the secret.
            value (str): The secret value.
            project (str): The project name.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        try:
            client = Secrets.load_vault(project)
            # Persist the secret
            secret = client.set_secret(secret_key, value)
            print(f"[Secrets] Successfully stored secret '{secret_key}' in Key Vault.")
            Secrets._cache[secret_key] = value  # Cache the value for local use
        except Exception as e:
            raise RuntimeError(f"[Secrets] Failed to store secret in Key Vault: {e}")

    @staticmethod
    def set(name: str, value: str, project: str, persist: bool = False) -> None:
        """
        Set the secret in cache and optionally persist it to Azure Key Vault.

        Args:
            name (str): The name of the secret.
            value (str): The secret value.
            project (str): The project name.
            persist (bool): Whether to persist the secret to Azure Key Vault. Default is False.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        # Store in local cache
        Secrets._cache[secret_key] = value
        print(f"[Secrets] Stored secret '{secret_key}' in cache.")

        # Optionally store the secret in Azure Key Vault
        if persist:
            Secrets.store(name, value, project)

    @staticmethod
    def has(name: str, project: str) -> bool:
        """
        Check if the secret exists in the cache or in Azure Key Vault.

        Args:
            name (str): The name of the secret.
            project (str): The project name.

        Returns:
            bool: True if the secret exists, False otherwise.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        if secret_key in Secrets._cache:
            return True

        try:
            client = Secrets.load_vault(project)
            client.get_secret(secret_key)  # Will raise if not found
            return True
        except Exception:
            return False

    @staticmethod
    def get(name: str, project: str, required: bool = True, store: bool = True) -> str | None:
        """
        Retrieve the secret from the cache or Azure Key Vault.

        Args:
            name (str): The name of the secret.
            project (str): The project name.
            required (bool): Whether the secret is required.
            store (bool): Whether to store the secret in the cache if found.

        Returns:
            str: The secret value.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        def return_secret(val):
            if store:
                Secrets._cache[secret_key] = val
            return val

        # Check cache first
        if secret_key in Secrets._cache:
            return return_secret(Secrets._cache[secret_key])

        # Check Key Vault
        try:
            client = Secrets.load_vault(project)
            val = client.get_secret(secret_key).value
            return return_secret(val)
        except Exception:
            pass

        if required:
            raise RuntimeError(f"[Secrets] Could not find secret: {secret_key}")
        return None

    @staticmethod
    def get_list(project: str) -> list[str]:
        """
        List all secrets in the Key Vault for a specific project.

        Args:
            project (str): The project name.

        Returns:
            list[str]: List of secret names.
        """
        client = Secrets.load_vault(project)
        prefix = f"{project}."
        results = []
        for prop in client.list_properties_of_secrets():
            if prop.name.startswith(prefix):
                try:
                    val = Secrets.get(prop.name[len(prefix):], project=project, required=False)
                    if val:
                        results.append(prop.name)
                except Exception:
                    continue
        return results

    @staticmethod
    def make_list(project: str) -> dict[str, str]:
        """
        Get all cached secrets for a specific project.

        Args:
            project (str): The project name.

        Returns:
            dict[str, str]: A dictionary of secret names and values.
        """
        prefix = f"{project}."
        return {
            key[len(prefix):]: val
            for key, val in Secrets._cache.items()
            if key.startswith(prefix)
        }

    @staticmethod
    def preload_cache(secrets: dict[str, str], project: str) -> None:
        """
        Preload multiple secrets into the cache.

        Args:
            secrets (dict): A dictionary of secret names and values.
            project (str): The project name.
        """
        if not isinstance(secrets, dict):
            raise TypeError("Expected a dictionary of secrets.")
        for k, v in secrets.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError(f"Secret keys/values must be strings. Got {k}={v}")
            Secrets._cache[f"{project}.{k}"] = v

    @staticmethod
    def clear_cache() -> None:
        """
        Clear the secret cache.
        """
        Secrets._cache.clear()
        Secrets._client = None


class Passwords:
    """
    A utility class for generating secure passwords with configurable options.
    """

    @staticmethod
    def generate_password(
            length: int = 16,
            min_length: int = 8,
            use_uppercase: bool = True,
            use_lowercase: bool = True,
            use_digits: bool = True,
            use_special_chars: bool = True
    ) -> str:
        """
        Generates a secure password that meets the specified complexity requirements.

        Args:
            length (int): Length of the password. Default is 16.
            min_length (int): Minimum length of the password. Default is 8.
            use_uppercase (bool): Whether to include uppercase letters. Default is True.
            use_lowercase (bool): Whether to include lowercase letters. Default is True.
            use_digits (bool): Whether to include digits. Default is True.
            use_special_chars (bool): Whether to include special characters. Default is True.

        Returns:
            str: The generated password.
        """
        print("[Passwords] Generating password now!")
        if length < min_length:
            raise ValueError(f"Password length should be at least {min_length} characters.")

        alphabet = ""
        if use_uppercase:
            alphabet += string.ascii_uppercase
        if use_lowercase:
            alphabet += string.ascii_lowercase
        if use_digits:
            alphabet += string.digits
        if use_special_chars:
            alphabet += string.punctuation

        if not alphabet:
            raise ValueError("At least one character type must be selected.")

        password = ''.join(secrets.choice(alphabet) for i in range(length))

        return password

    @staticmethod
    def generate_simple_password(length: int = 12) -> str:
        """
        Generates a simple password with default settings:
        - Length: 12 characters
        - Includes lowercase, uppercase, digits, and special characters.

        Args:
            length (int): Length of the password. Default is 12.

        Returns:
            str: The generated simple password.
        """
        return Passwords.generate_password(length=length)

    @staticmethod
    def validate_password(password: str) -> bool:
        """
        Validates the password complexity by checking its length and character types.

        Args:
            password (str): The password to validate.

        Returns:
            bool: True if the password meets the criteria, False otherwise.
        """
        if len(password) < 8:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.islower() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        if not any(c in string.punctuation for c in password):
            return False
        return True

    @staticmethod
    def get(name: str, project: str, length: int = 16) -> str:
        """
        Retrieves the password from the environment if it exists,
        otherwise generates and stores a new password for future use.

        Args:
            name: The password key for identifying it.
            project (str): The project name to associate the password with.
            length (int): Length of the password. Default is 16.

        Returns:
            str: The password (either retrieved from env or newly generated).
        """
        # Try to get the password from the environment
        print(f"[Passwords] Attempting to get password for {name} ...")
        password = Secrets.get(name, project, required=False, store=True)
        print(password)
        valid_password = None

        # If the password is not found, generate and store a new one
        if not password:
            print(f"[Passwords] No password found! Generating ...")
            password = Passwords.generate_password(length)
            Secrets.set(name, password, project, persist=True)

        if password:
            print(f"[Password] Password found.")
            valid_password = Passwords.validate_password(password)
            if valid_password is False: valid_password = Passwords.generate_password(length)

        print(f"[Passwords] Password successfully initialized!")

        return valid_password
