import logging
import secrets as _secrets
import string
import time
from typing import Optional, Dict, List

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.keyvault import KeyVaultManagementClient

import context.milescontext as mc
from context.cache import Cache
from context.milescontext import cache
from milesazure.client import AzureClient
from milesazure.run import run_az
from milesazure.tenant import AzureSubscription, AzureResourceGroup

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
    Securely manage secrets using Azure Key Vault with an in‐memory cache fallback.
    """

    _cache: Dict[str, str] = {}

    @staticmethod
    def sanitize(key: str) -> str:
        """
        Purge unsafe characters from a key.
        Args:
            key (str): Raw key name.
        Returns:
            str: Sanitized key.
        """
        if not isinstance(key, str):
            raise TypeError("Secrets.sanitize: key must be a string")
        sanitized = key.replace(" ", "_")  # example purge; replace with sanny.purge if available
        return sanitized

    @staticmethod
    def _get_credential(project: str) -> DefaultAzureCredential | ClientSecretCredential:
        """
        Choose Azure credential: prefer ClientSecretCredential if all Azure IDs/secrets are cached,
        else fallback to DefaultAzureCredential.
        Args:
            project (str): Project name.
        Returns:
            DefaultAzureCredential or ClientSecretCredential
        """
        if not isinstance(project, str):
            raise TypeError("Secrets._get_credential: project must be a string")

        # Defined variables
        tenant_id = Cache.get(project, "AZURE_TENANT_ID")
        client_id = Cache.get(project, "AZURE_CLIENT_ID")
        client_secret = Cache.temp_get(project, "AZURE_CLIENT_SECRET") or Cache.get(project, "AZURE_CLIENT_SECRET")

        # Logic
        if tenant_id and client_id and client_secret:
            logger.debug("[Secrets] Using ClientSecretCredential for project: %s", project)
            return ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)

        logger.debug("[Secrets] Falling back to DefaultAzureCredential for project: %s", project)
        return DefaultAzureCredential()

    @staticmethod
    def load_vault(project: Optional[str] = None) -> SecretClient:
        """
        Instantiate or return a SecretClient for the project's Key Vault.
        Args:
            project (str | None): Project name; if None, attempts to retrieve 'selected_project'.
        Returns:
            SecretClient: Azure Key Vault client.
        Raises:
            RuntimeError: If project is not specified or vault cannot be accessed.
        """
        if project is None:
            project = Cache.get("global", "selected_project_name")
        if not project:
            raise RuntimeError("Secrets.load_vault: no project specified or selected")

        # Defined variables
        vault_uri = Cache.get(project, "VAULT_URI")

        # Logic: ensure vault exists
        if not vault_uri:
            logger.warning("[Secrets] VAULT_URI missing; creating vault for project: %s", project)
            vault_uri = VaultSetup.ensure_vault_ready(project)
            if not isinstance(vault_uri, str):
                raise RuntimeError("Secrets.load_vault: invalid VAULT_URI returned")

        try:
            credential = Secrets._get_credential(project)
            client = SecretClient(vault_url=vault_uri, credential=credential)
            return client
        except Exception as e:
            raise RuntimeError(f"Secrets.load_vault: failed to load Key Vault client: {e}")

    @staticmethod
    def store(name: str, value: str, project: str) -> None:
        """
        Persist a secret to Azure Key Vault and cache it in memory.
        Args:
            name (str): Secret name (no project prefix).
            value (str): Secret value.
            project (str): Project name.
        Raises:
            RuntimeError: On failure to store.
        """
        if not all(isinstance(x, str) for x in (name, value, project)):
            raise TypeError("Secrets.store: name, value, and project must be strings")

        # Defined variables
        raw_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(raw_key)

        # Logic
        try:
            client = Secrets.load_vault(project)
            client.set_secret(secret_key, value)
            Secrets._cache[secret_key] = value
            logger.info("Stored secret '%s' in Key Vault", secret_key)
        except Exception as e:
            raise RuntimeError(f"Secrets.store: failed to store secret '{secret_key}': {e}")

    @staticmethod
    def set(name: str, value: str, project: str, persist: bool = False) -> None:
        """
        Cache a secret locally and optionally persist to Azure Key Vault.
        Args:
            name (str): Secret name.
            value (str): Secret value.
            project (str): Project name.
            persist (bool): If True, also store in Key Vault.
        Raises:
            TypeError: If arguments are not strings.
        """
        if not all(isinstance(x, str) for x in (name, value, project)):
            raise TypeError("Secrets.set: name, value, and project must be strings")

        # Defined variables
        raw_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(raw_key)

        # Logic: cache locally
        Secrets._cache[secret_key] = value
        logger.debug("Cached secret '%s'", secret_key)

        if persist:
            Secrets.store(name, value, project)

    @staticmethod
    def has(name: str, project: str) -> bool:
        """
        Check if a secret exists in local cache or in Key Vault.
        Args:
            name (str): Secret name.
            project (str): Project name.
        Returns:
            bool: True if secret exists.
        """
        if not all(isinstance(x, str) for x in (name, project)):
            raise TypeError("Secrets.has: name and project must be strings")

        # Defined variables
        raw_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(raw_key)

        # Logic: check cache
        if secret_key in Secrets._cache:
            return True

        # Check Key Vault
        try:
            client = Secrets.load_vault(project)
            client.get_secret(secret_key)
            return True
        except Exception:
            return False

    @staticmethod
    def get(name: str, project: str, required: bool = True, store: bool = True) -> Optional[str]:
        """
        Retrieve a secret from cache or Key Vault.
        Args:
            name (str): Secret name.
            project (str): Project name.
            required (bool): If True, raise if not found.
            store (bool): If True, cache retrieved value.
        Returns:
            str | None: Secret value or None.
        Raises:
            RuntimeError: If required and secret not found.
        """
        if not all(isinstance(x, str) for x in (name, project)):
            raise TypeError("Secrets.get: name and project must be strings")

        # Defined variables
        raw_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(raw_key)

        # Logic: check in-memory cache
        if secret_key in Secrets._cache:
            val = Secrets._cache[secret_key]
            if store:
                logger.debug("Retrieved secret '%s' from local cache", secret_key)
            return val

        # Attempt Key Vault retrieval
        try:
            client = Secrets.load_vault(project)
            secret_bundle = client.get_secret(secret_key)
            val = secret_bundle.value
            if store:
                Secrets._cache[secret_key] = val
                logger.debug("Retrieved secret '%s' from Key Vault", secret_key)
            return val
        except Exception:
            if required:
                raise RuntimeError(f"Secrets.get: could not find secret '{secret_key}'")
            return None

    @staticmethod
    def get_list(project: str) -> List[str]:
        """
        List names of all secrets for a project in Key Vault.
        Args:
            project (str): Project name.
        Returns:
            List[str]: List of secret names (including project prefix).
        """
        if not isinstance(project, str):
            raise TypeError("Secrets.get_list: project must be a string")

        # Logic
        client = Secrets.load_vault(project)
        prefix = f"{project}."
        names: List[str] = []
        for prop in client.list_properties_of_secrets():
            if prop.name.startswith(prefix):
                names.append(prop.name)
        return names

    @staticmethod
    def make_list(project: str) -> Dict[str, str]:
        """
        Return all secrets cached in-memory for a project.
        Args:
            project (str): Project name.
        Returns:
            Dict[str, str]: Mapping from secret name to value.
        """
        if not isinstance(project, str):
            raise TypeError("Secrets.make_list: project must be a string")

        prefix = f"{project}."
        result = {
            key[len(prefix):]: val
            for key, val in Secrets._cache.items()
            if key.startswith(prefix)
        }
        return result

    @staticmethod
    def preload_cache(secrets: Dict[str, str], project: str) -> None:
        """
        Bulk load secrets into in-memory cache without persisting.
        Args:
            secrets (Dict[str, str]): Mapping of name to value.
            project (str): Project name.
        Raises:
            TypeError: If secret keys/values are not strings.
        """
        if not isinstance(secrets, dict) or not isinstance(project, str):
            raise TypeError("Secrets.preload_cache: arguments must be (dict, str)")
        for k, v in secrets.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError("Secrets.preload_cache: keys and values must be strings")
            secret_key = Secrets.sanitize(f"{project}.{k}")
            Secrets._cache[secret_key] = v
        logger.info("Preloaded %d secrets into cache for project '%s'", len(secrets), project)

    @staticmethod
    def clear_cache() -> None:
        """
        Clear all in-memory secret cache.
        """
        Secrets._cache.clear()
        logger.info("Cleared all secrets from in-memory cache")


class Passwords:
    """
    Generate, validate, and manage passwords via Secrets.
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
        Create a random password meeting complexity requirements.
        Args:
            length (int): Desired total length.
            min_length (int): Minimum allowed length.
            use_uppercase (bool): Include uppercase letters.
            use_lowercase (bool): Include lowercase letters.
            use_digits (bool): Include digits.
            use_special_chars (bool): Include symbols.
        Returns:
            str: Generated password.
        Raises:
            ValueError: If length < min_length or no character sets selected.
        """
        if not isinstance(length, int) or not isinstance(min_length, int):
            raise TypeError("Passwords.generate_password: length and min_length must be ints")
        if length < min_length:
            raise ValueError(f"Password length {length} < minimum {min_length}")

        # Defined variables
        alphabet = ""
        if use_uppercase:
            alphabet += string.ascii_uppercase
        if use_lowercase:
            alphabet += string.ascii_lowercase
        if use_digits:
            alphabet += string.digits
        if use_special_chars:
            alphabet += string.punctuation

        # Logic
        if not alphabet:
            raise ValueError("No character categories selected for password")

        pwd = "".join(_secrets.choice(alphabet) for _ in range(length))
        return pwd

    @staticmethod
    def generate_simple_password(length: int = 12) -> str:
        """
        Create a default-complexity password of given length.
        Args:
            length (int): Password length.
        Returns:
            str: Generated password.
        """
        return Passwords.generate_password(length=length)

    @staticmethod
    def validate_password(password: str) -> bool:
        """
        Ensure a password is at least 8 characters and contains upper, lower, digit, and symbol.
        Args:
            password (str): Password to validate.
        Returns:
            bool: True if valid, False otherwise.
        """
        if not isinstance(password, str):
            raise TypeError("Passwords.validate_password: password must be a string")
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
        Retrieve or generate a password, storing it via Secrets if missing.
        Args:
            name (str): Password key name.
            project (str): Project name.
            length (int): Desired password length.
        Returns:
            str: Valid password.
        Raises:
            RuntimeError: If password cannot be retrieved/generated.
        """
        if not all(isinstance(x, str) for x in (name, project)):
            raise TypeError("Passwords.get: name and project must be strings")
        if not isinstance(length, int):
            raise TypeError("Passwords.get: length must be an integer")

        # Logic: try retrieving existing
        logger.debug("Attempting to retrieve password '%s' for project '%s'", name, project)
        existing = Secrets.get(name, project, required=False, store=True)
        if existing and Passwords.validate_password(existing):
            logger.info("Password '%s' retrieved from vault", name)
            return existing

        # Generate new password
        logger.info("No valid password found; generating a new one")
        new_pwd = Passwords.generate_password(length=length)
        Secrets.set(name, new_pwd, project, persist=True)
        logger.info("Generated and stored new password '%s' for project '%s'", name, project)
        return new_pwd
