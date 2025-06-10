import logging
import secrets as _secrets
import string
from typing import Dict, Any, Optional, List

from azure.core.credentials import TokenCredential
from azure.keyvault.secrets import SecretClient

import milesazure.run as run
import util
from context.cache import Cache
from context.milescontext import cache
from milesazure.client import AzureClient
from milesazure.run import run_az
from milesazure.tenant import AzureResourceGroup
from milesazure.tenant import AzureSubscription

logger = logging.getLogger(__name__)


class Secrets:
    """
    Securely manage secrets using Azure Key Vault with an in-memory cache fallback.
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
        sanny = util.sanitization.Sanitization.standard(key)
        return sanny

    @staticmethod
    def _test_secrets(project: str):
        key, value = ("test", "test")
        if Secrets.has(project, key) is False:
            Secrets.set(project, key, value)
        Secrets.get(project, key)

    @staticmethod
    def load_vault(project: Optional[str] = None) -> str:
        """
        Instantiate or return a SecretClient for the project's Key Vault.
        Args:
            project (str | None): Project name; if None, retrieves 'selected_project_name' from cache.
        Returns:
            SecretClient: Azure Key Vault client.
        Raises:
            RuntimeError: If project is not specified or vault cannot be accessed.
        """
        if project is None:
            project = Cache.get("global", "selected_project_name")
        if not project:
            raise RuntimeError("Secrets.load_vault: no project specified or selected")
        try: vault_name = cache.get(project, "VAULT_NAME", VaultSetup.get_vault(project)["VAULT_NAME"])
        except Exception as e: raise RuntimeError(f"Vault loading failed!: {e}")

        if Secrets.vault_tested is False:
            Secrets._test_secrets(project)
            logger.info("Vault connection works! Thank god.")

        return vault_name

    @staticmethod
    def set(namespace: str, name: str, value: str) -> None:
        """
        Persist a secret to Azure Key Vault and cache it in memory.
        Args:
            namespace (str): Project name.
            name (str): Secret name (no project prefix).
            value (str): Secret value.
        Raises:
            RuntimeError: On failure to store.
        """
        if not all(isinstance(x, str) for x in (name, value, namespace)):
            raise TypeError("Secrets.store: name, value, and project must be strings")

        raw_key = f"{namespace}-{name}"
        secret_key = Secrets.sanitize(raw_key)
        vault_name = Secrets.load_vault(namespace)

        try:
            run.set_secret(vault_name, name, value)
        except Exception as e:
            raise RuntimeError(f"Secrets.store: failed to store secret '{secret_key}': {e}")

    @staticmethod
    def has(namespace: str, name: str) -> bool | None:
        """
        Check if a secret exists in local cache or in Key Vault.
        Args:
            namespace (str): Project name.
            name (str): Secret name.
        Returns:
            bool: True if secret exists.
        """
        if not all(isinstance(x, str) for x in (name, namespace)):
            raise TypeError("Secrets.has: name and project must be strings")

        raw_key = f"{namespace}_{name}"
        secret_key = Secrets.sanitize(raw_key)
        vault_name = Secrets.load_vault(namespace)

        if secret_key in Secrets._cache:
            return True

        try:
            sec = Secrets.get(namespace, name)
            if sec is not None: return True
        except Exception as e:
            logger.warning(f"Could not find secret!: {e}")
            return False

    @staticmethod
    def get(namespace: str, name: str, required: bool = True, store: bool = True) -> Optional[str]:
        """
        Retrieve a secret from cache or Key Vault.
        Args:
            name (str): Secret name.
            namespace (str): Project name.
            required (bool): If True, raise if not found.
            store (bool): If True, cache retrieved value.
        Returns:
            str | None: Secret value or None.
        Raises:
            RuntimeError: If required and secret not found.
        """
        if not all(isinstance(x, str) for x in (name, namespace)):
            raise TypeError("Secrets.get: name and project must be strings")

        raw_key = f"{namespace}_{name}"
        secret_key = Secrets.sanitize(raw_key)
        vault_name = Secrets.load_vault(namespace)

        if secret_key in Secrets._cache:
            val = Secrets._cache[secret_key]
            if store:
                logger.debug("[Secrets] Retrieved secret '%s' from local cache", secret_key)
            return val

        try:
            sec = run.show_secret(vault_name, name)
            val = sec[""]
            if store:
                Secrets._cache[secret_key] = val
                logger.debug("[Secrets] Retrieved secret '%s' from Key Vault", secret_key)
            return val
        except Exception:
            if required:
                raise RuntimeError(f"Secrets.get: could not find secret '{secret_key}'")
            return None

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
            raise ValueError("No character categories selected for password")

        return "".join(_secrets.choice(alphabet) for _ in range(length))

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

        logger.debug("[Passwords] Attempting to retrieve password '%s' for project '%s'.", name, project)
        existing = Secrets.get(project, name, required=False, store=True)
        if existing and Passwords.validate_password(existing):
            logger.info("[Passwords] Password '%s' retrieved from vault.", name)
            return existing

        logger.info("[Passwords] No valid password found; generating a new one.")
        new_pwd = Passwords.generate_password(length=length)
        Secrets.set(name, new_pwd, project, persist=True)
        logger.info("[Passwords] Generated and stored new password '%s' for project '%s'.", name, project)
        return new_pwd


class VaultSetup:
    """
    Utility class to manage Azure Key Vault lifecycle for a given project.
    Responsibilities:
      - Check whether the Key Vault exists.
      - Create the Key Vault if it does not exist.
      - Fetch or cache vault metadata (name, URI, location, resource ID).
      - Provide methods to store and retrieve secrets via the `Secrets` class.
      - Determine the Azure object ID of the current application/service principal.
    """

    class CLI:
        """
        Nested helper class to run Azure CLI commands related to Key Vault.
        """

        @staticmethod
        def show_vault(vault_name: str, subscription_id: str) -> Dict[str, Any]:
            """
            Use `az keyvault show` to fetch existing vault metadata.

            Args:
                vault_name (str): Name of the Key Vault.
                subscription_id (str): Azure subscription ID.

            Returns:
                Dict[str, Any]: Parsed JSON response from CLI.

            Raises:
                KeyError: If vault not found.
                RuntimeError: If CLI call fails for other reasons.
            """
            try:
                result = run_az(
                    [
                        "az", "keyvault", "show",
                        "--name", vault_name,
                        "--subscription", subscription_id,
                        "--output", "json"
                    ],
                    capture_output=True
                )
                logger.debug(
                    "[VaultSetup.CLI] Vault '%s' exists in subscription '%s'. Metadata: %s",
                    vault_name, subscription_id, result
                )
                return result
            except Exception as ex:
                stderr = str(ex).lower()
                if "not found" in stderr or "resource not found" in stderr or "not exist" in stderr:
                    logger.debug("[VaultSetup.CLI] Vault '%s' not found.", vault_name)
                    raise KeyError("VaultNotFound")
                raise RuntimeError(f"[VaultSetup.CLI] Error checking vault existence: {ex}")

        @staticmethod
        def create_vault(
                vault_name: str,
                resource_group: str,
                location: str,
                subscription_id: str
        ) -> Dict[str, Any]:
            """
            Use `az keyvault create` to create a new Key Vault with RBAC authorization.

            Args:
                vault_name (str): Name of the Key Vault to create.
                resource_group (str): Resource group in which to create the vault.
                location (str): Azure region (e.g., "eastus").
                subscription_id (str): Azure subscription ID.

            Returns:
                Dict[str, Any]: Parsed JSON response from CLI.

            Raises:
                RuntimeError: If CLI call fails for any reason.
            """
            try:
                result = run_az(
                    [
                        "az", "keyvault", "create",
                        "--name", vault_name,
                        "--resource-group", resource_group,
                        "--location", location,
                        "--enable-rbac-authorization", "true",
                        "--subscription", subscription_id,
                        "--output", "json"
                    ],
                    capture_output=True
                )
                logger.info(
                    "[VaultSetup.CLI] Created Key Vault '%s' in resource group '%s' (location='%s').",
                    vault_name, resource_group, location
                )
                return result
            except Exception as ex:
                raise RuntimeError(f"[VaultSetup.CLI] Failed to create vault '{vault_name}': {ex}")

    @staticmethod
    def _validate_project(project: str) -> None:
        """
        Validate that `project` is a non-empty string.

        Raises:
            TypeError: If `project` is not a non-empty string.
        """
        if not isinstance(project, str) or not project.strip():
            raise TypeError("VaultSetup: 'project' must be a non-empty string")

    @staticmethod
    def ensure_vault_ready(project: str) -> Dict[str, Any]:
        """
        Ensure that the Key Vault for `project` exists and cache its metadata.

        Variables:
            subscription_id: str
            resource_group: str
            region: str
            vault_name: str
            raw_meta: Dict[str, Any]
            metadata: Dict[str, Any]

        Logic:
            1. Validate `project`.
            2. Retrieve or compute:
                 - subscription_id = Cache.get(..., recall=lambda: AzureSubscription.get(project))
                 - resource_group  = Cache.get(..., recall=lambda: AzureResourceGroup.get(project))
                 - region          = Cache.get(..., recall=lambda: "eastus")
                 - vault_name      = Cache.get(..., recall=lambda: f"{project}-vault")
            3. Attempt to fetch existing vault via CLI:
               a. If exists, parse JSON into raw_meta.
               b. If not found (KeyError), call CLI to create vault; raw_meta = create response.
            4. Normalize metadata into:
                 {
                   "VAULT_NAME": raw_meta["name"],
                   "VAULT_URI": raw_meta["properties"]["vaultUri"],
                   "VAULT_LOCATION": raw_meta["location"],
                   "VAULT_ID": raw_meta["id"]
                 }
            5. Cache each of those under:
                 Cache.set(project, "<KEY>", value, include_in_cfg=project)
            6. Return normalized metadata.
        """
        subscription_id = Cache.get(
            project,
            "AZURE_SUBSCRIPTION_ID",
            recall=lambda: AzureSubscription.get(project)
        )
        resource_group = Cache.get(
            project,
            "RESOURCE_GROUP",
            recall=lambda: AzureResourceGroup.get(project)
        )
        region = Cache.get(
            project,
            "AZURE_REGION",
            recall=lambda: "eastus"
        )
        vault_name = Cache.get(
            project,
            "VAULT_NAME",
            recall=lambda: f"{project}-vault"
        )

        logger.debug(
            "[VaultSetup] ensure_vault_ready: project='%s', sub_id='%s', rg='%s', region='%s', vault_name='%s'",
            project, subscription_id, resource_group, region, vault_name
        )

        try:
            raw_meta = VaultSetup.CLI.show_vault(vault_name, subscription_id)
        except KeyError:
            raw_meta = VaultSetup.CLI.create_vault(
                vault_name, resource_group, region, subscription_id
            )

        name_val = raw_meta.get("name", "")
        uri_val = raw_meta.get("properties", {}).get("vaultUri", "")
        location_val = raw_meta.get("location", "")
        id_val = raw_meta.get("id", "")

        if not all(isinstance(x, str) and x for x in (name_val, uri_val, location_val, id_val)):
            raise RuntimeError(f"[VaultSetup] Invalid vault metadata returned: {raw_meta}")

        Cache.set(project, "VAULT_NAME", name_val, include_in_cfg=project)
        Cache.set(project, "VAULT_URI", uri_val, include_in_cfg=project)
        Cache.set(project, "VAULT_LOCATION", location_val, include_in_cfg=project)
        Cache.set(project, "VAULT_ID", id_val, include_in_cfg=project)

        logger.info(
            "[VaultSetup] Cached vault metadata for project '%s': name='%s', uri='%s', location='%s', id='%s'",
            project, name_val, uri_val, location_val, id_val
        )

        return {
            "VAULT_NAME": name_val,
            "VAULT_URI": uri_val,
            "VAULT_LOCATION": location_val,
            "VAULT_ID": id_val,
        }

    @staticmethod
    def get_vault(project: str) -> Dict[str, Any]:
        """
        Retrieve Key Vault metadata for the given project, creating the vault if needed.

        Logic:
            1. Validate `project`.
            2. Call ensure_vault_ready(project) to create/fetch and cache metadata.
            3. Read and return cached values:
                 - VAULT_NAME, VAULT_URI, VAULT_LOCATION, VAULT_ID
        """
        if not isinstance(project, str) or not project.strip():
            raise TypeError("VaultSetup.get_vault: 'project' must be a non-empty string")

        meta = VaultSetup.ensure_vault_ready(project)

        missing = [k for k, v in meta.items() if not isinstance(v, str) or not v]
        if missing:
            raise RuntimeError(f"[VaultSetup] Missing vault keys {missing} for project '{project}'")

        logger.debug("[VaultSetup] get_vault returning metadata for '%s': %s", project, meta)
        return meta

    @staticmethod
    def load_vault(project: str) -> SecretClient:
        """
        Instantiate and return a SecretClient for the project's Key Vault.

        Logic:
            1. Validate `project`.
            2. Call get_vault(project) to fetch URI.
            3. Create DefaultAzureCredential or ClientSecretCredential, then SecretClient.
        """
        if not isinstance(project, str) or not project.strip():
            raise TypeError("VaultSetup.load_vault: 'project' must be a non-empty string")

        meta = VaultSetup.get_vault(project)
        vault_uri = meta.get("VAULT_URI", "")
        if not isinstance(vault_uri, str) or not vault_uri:
            raise RuntimeError(f"[VaultSetup] Invalid VAULT_URI for project '{project}': {vault_uri}")

        try:
            client = SecretClient(vault_url=vault_uri, credential=TokenCredential())
            logger.info("[VaultSetup] Created SecretClient for vault '%s'.", vault_uri)
            return client
        except Exception as ex:
            raise RuntimeError(f"[VaultSetup] Failed to create SecretClient for '{vault_uri}': {ex}")

    @staticmethod
    def get_current_object_id(project: str) -> str:
        """
        Retrieve the Azure object ID for the current service principal or application.

        Logic:
            1. Validate `project`.
            2. Fetch or cache:
                 client_id = Cache.get(..., recall=lambda: AzureClient.get(project)["appId"])
                 object_id = Cache.get(..., recall=lambda: AzureClient.get(project)["id"])
            3. Return object_id.
        """
        if not isinstance(project, str) or not project.strip():
            raise TypeError("VaultSetup.get_current_object_id: 'project' must be a non-empty string")

        client_id = Cache.get(
            project,
            "AZURE_CLIENT_ID",
            recall=lambda: AzureClient.get(project).get("appId", "")
        )
        if not isinstance(client_id, str) or not client_id:
            raise RuntimeError(f"[VaultSetup] Unable to resolve AZURE_CLIENT_ID for '{project}'")

        object_id = Cache.get(
            project,
            "SP_OBJECT_ID",
            recall=lambda: AzureClient.get(project).get("id", "")
        )
        if not isinstance(object_id, str) or not object_id:
            raise RuntimeError(f"[VaultSetup] Unable to resolve SP_OBJECT_ID for '{project}'")

        logger.debug(
            "[VaultSetup] get_current_object_id for project '%s': client_id='%s', object_id='%s'",
            project, client_id, object_id
        )
        return object_id


# Convenience wrappers in vault that use Secrets and Passwords

def store_secret(name: str, value: str, project: str) -> None:
    """
    Wrapper around Secrets.store to persist a secret in Key Vault.
    """
    Secrets.store(name, value, project)


def retrieve_secret(name: str, project: str, required: bool = True) -> Optional[str]:
    """
    Wrapper around Secrets.get to retrieve a secret by name.
    """
    return Secrets.get(project, name, required=required, store=True)


def list_local_secrets(project: str) -> Dict[str, str]:
    """
    Return all secrets cached in-memory for a project.
    """
    return Secrets.make_list(project)


def list_vault_secrets(project: str) -> List[str]:
    """
    List all secret names stored in Key Vault for a project.
    """
    return Secrets.get_list(project)


def get_or_generate_password(name: str, project: str, length: int = 16) -> str:
    """
    Retrieve an existing password or generate a new one via Passwords.get.
    """
    return Passwords.get(name, project, length=length)
