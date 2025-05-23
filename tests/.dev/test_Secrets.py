import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

DEFAULT_PROJECT_NAME = "default_project"
CURRENT_PROJECT_NAME = None
SEL_PROJECT_NAME = CURRENT_PROJECT_NAME or DEFAULT_PROJECT_NAME
#SEL_PROJECT_PATH = sm.cfg_get
AZURE_CRED = DefaultAzureCredential()

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
    def load_vault(sel_project = SEL_PROJECT_NAME) -> SecretClient | None:
        """
        Initializes the Azure Key Vault client if KEY_VAULT_URL is configured.
        Returns:
            A SecretClient instance or None if KEY_VAULT_URL is not set or fails.
        """
        url = os.getenv(f"{sel_project}.KEY_VAULT_URL")
        cur_client = Secrets._client
        if not url: raise ValueError("Vault URL not set!")

        def cache_client(client):
            Secrets._client = client

        def load_client():
            if cur_client: return cur_client
            try:
                return SecretClient(vault_url=url, credential=AZURE_CRED)
            except Exception:
                raise RuntimeError

        client = load_client()
        if not cur_client: cache_client(client)
        return client

    @staticmethod
    def set(name: str, value: str, sel_project: str = SEL_PROJECT_NAME) -> None:
        """
        Sets a secret in the in-memory cache. This does not persist to disk or Azure Vault.

        Args:
            name: The name of the secret (e.g. "aad-app-id").
            value: The secret value to store.
            sel_project: Project namespace to scope the secret.

        Raises:
            TypeError: If name or value are not strings.
        """
        if not isinstance(name, str):
            raise TypeError("Secret name must be a string.")
        if not isinstance(value, str):
            raise TypeError("Secret value must be a string.")

        secret_name = f"{sel_project}.{name}"
        Secrets._cache[secret_name] = value

    @staticmethod
    def has(name: str, sel_project: str = SEL_PROJECT_NAME) -> bool:
        """
        Returns True if the secret exists in cache, Azure Key Vault, or environment.

        Args:
            name: The name of the secret (e.g. "aad-app-id").
            sel_project: Project namespace.

        Returns:
            bool: True if the secret was found, False otherwise.
        """
        try:
            return Secrets.get(name=name, sel_project=sel_project, required=False) is not None
        except Exception:
            return False

    @staticmethod
    def get(name: str, sel_project: str = SEL_PROJECT_NAME, required: bool = True, store: bool = True) -> str | None:
        """
        Retrieves a secret by name.

        Order of resolution:
            1. In-memory cache
            2. Azure Key Vault (if configured)
            3. OS environment variables

        Args:
            name: The name of the secret (e.g. "aad-app-id").
            required: If True, raise if secret not found.

        Returns:
            The secret value, or None if not required and not found.

        Raises:
            RuntimeError: If the secret is required but not found.
            None: If the secret is not required.
        """
        secret_name = f"{sel_project}.{name}"
        cache = Secrets._cache
        k = secret_name
        v = None

        def return_secret(k, v):
            if store and k not in cache:
                cache[k] = v
            return v

        def get_secret_from_cache(k):
            if k in cache:
                v = cache[k]
                return return_secret(k, v)
            raise LookupError

        def get_secret_from_azure(k):
            client = Secrets.load_vault(sel_project)
            try:
                v = client.get_secret(k).value
                if v: return return_secret(k, v)
                raise LookupError
            except Exception:
                raise LookupError

        def get_secret_from_env(k):
            v = os.getenv(k)
            if v: return return_secret(k, v)
            raise LookupError

        methods = [get_secret_from_cache, get_secret_from_azure, get_secret_from_env]

        for method in methods:
            try: return method(k)
            except (LookupError, Exception): continue

        # 5. If still not found and required=True, raise RuntimeError
        if required: raise RuntimeError(f"Could not find {secret_name}! Crashing program, lol.")
        else: return None

    @staticmethod
    def make_list(sel_project: str = SEL_PROJECT_NAME) -> dict[str, str]:
        """
        Returns a dict of {secret_name: value} for all secrets cached under a project.

        Args:
            sel_project: Project namespace to filter by.

        Returns:
            Dict of secrets with short keys (without project prefix).
        """
        prefix = f"{sel_project}."
        return {
            key[len(prefix):]: value
            for key, value in Secrets._cache.items()
            if key.startswith(prefix)
        }

    @staticmethod
    def get_list(sel_project: str = SEL_PROJECT_NAME) -> list[str]:
        """
        Retrieves a list of fully-qualified secret keys from Azure Key Vault that
        start with the given project prefix and are resolvable via Secrets.get().

        Args:
            sel_project: The project prefix (e.g., "proj")

        Returns:
            List of "proj.secret" strings that exist in Azure Key Vault.
        """
        keys = []
        prefix = f"{sel_project}."
        client = Secrets.load_vault(sel_project)
        if not client:
            raise RuntimeError("Vault client could not be initialized.")

        def find_secrets(prefix):
            for prop in client.list_properties_of_secrets():
                if prop.name.startswith(prefix):
                    try:
                        val = Secrets.get(name=prop.name[len(prefix):], sel_project=sel_project, required=False)
                        if val is not None:
                            keys.append(prop.name)
                    except Exception:
                        continue

        try: find_secrets(prefix)
        except Exception as e: raise RuntimeError(f"Failed to fetch secret list: {e}")
        return keys

    @staticmethod
    def preload_cache(secrets: list, sel_project: str = SEL_PROJECT_NAME) -> None:
        """
        Bulk loads a dictionary of secrets into the in-memory cache.
        Does not persist to disk or Azure Key Vault.

        Args:
            secrets: Dict of {name: value} pairs.
            sel_project: Project namespace for all secrets.

        Raises:
            TypeError: If secrets is not a dictionary or keys/values are not strings.
        """
        if not isinstance(secrets, dict):
            raise TypeError("preload() expects a dictionary of secrets.")

        for k, v in secrets.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError(f"Secret keys and values must be strings. Got: {k}={v}")
            full_key = f"{sel_project}.{k}"
            Secrets._cache[full_key] = v

    @staticmethod
    def clear_cache() -> None:
        """
        Clears the in-memory secrets cache and Azure client reference.
        Useful for testing, forced refresh, or resetting between project scopes.
        """
        Secrets._cache.clear()
        Secrets._client = None

import os
import pytest
from unittest.mock import patch, MagicMock

# ─── DUMMY AZURE VAULT CLIENTS ─────────────────────────────────────

class DummySecret:
    def __init__(self, value):
        self.value = value

class DummySecretClient:
    def __init__(self, vault_url, credential):
        self.vault_url = vault_url
        self.credential = credential
        self.secrets = {
            "proj.secret": DummySecret("vault-value")
        }

    def get_secret(self, name):
        if name in self.secrets:
            return self.secrets[name]
        raise Exception("Not found")

class DummyCredential:
    pass

class EmptyVaultClient:
    def __init__(self, *args, **kwargs):
        self.secrets = {}

    def get_secret(self, name):
        raise LookupError("Not found")

import pytest
import os

@pytest.fixture(autouse=True)
def setup(monkeypatch):
    # Clear cache before and after each test
    Secrets._cache.clear()
    monkeypatch.setenv("proj.KEY_VAULT_URL", "https://dummy.vault")
    monkeypatch.setattr("test_Secrets.SecretClient", DummySecretClient)
    monkeypatch.setattr("test_Secrets.DefaultAzureCredential", DummyCredential)
    yield
    Secrets._cache.clear()

def test_returns_from_cache_first():
    Secrets._cache["proj.secret"] = "cached-value"
    result = Secrets.get("secret", "proj")
    assert result == "cached-value"

def test_returns_from_env_if_not_in_cache(monkeypatch):
    from test_Secrets import DummyCredential, EmptyVaultClient

    monkeypatch.setenv("proj.KEY_VAULT_URL", "https://dummy.vault")
    monkeypatch.setenv("proj.secret", "env-value")
    monkeypatch.setattr("test_Secrets.SecretClient", EmptyVaultClient)
    monkeypatch.setattr("test_Secrets.DefaultAzureCredential", DummyCredential)

    result = Secrets.get("secret", "proj")
    assert result == "env-value"
    assert Secrets._cache["proj.secret"] == "env-value"


def test_returns_from_vault_if_not_in_cache_or_env(monkeypatch):
    class DummySecret:
        def __init__(self, value):
            self.value = value

    class DummyVaultClient:
        def get_secret(self, name):
            if name == "proj.secret":
                return DummySecret("vault-value")
            raise Exception("Not found")

    monkeypatch.setenv("proj.KEY_VAULT_URL", "https://dummy.vault")
    monkeypatch.setattr("test_Secrets.Secrets._client", DummyVaultClient())

    monkeypatch.delenv("proj.secret", raising=False)

    result = Secrets.get("secret", "proj")
    assert result == "vault-value"


def test_raises_if_required_and_not_found(monkeypatch):
    monkeypatch.delenv("proj.secret", raising=False)

    class EmptyVaultClient(DummySecretClient):
        def __init__(self, *args, **kwargs):
            self.secrets = {}

    monkeypatch.setattr("test_Secrets.SecretClient", EmptyVaultClient)

    with pytest.raises(RuntimeError):
        Secrets.get("proj", "secret", required=True)

def test_returns_none_if_not_required_and_not_found(monkeypatch):
    monkeypatch.delenv("proj.secret", raising=False)

    class EmptyVaultClient(DummySecretClient):
        def __init__(self, *args, **kwargs):
            self.secrets = {}

    monkeypatch.setattr("test_Secrets.SecretClient", EmptyVaultClient)

    result = Secrets.get("proj", "secret", required=False)
    assert result is None

import os
import pytest

@pytest.fixture(autouse=True)
def clear_state():
    Secrets.clear_cache()
    yield
    Secrets.clear_cache()

def test_set_and_make_list():
    Secrets.set("token", "abc123", sel_project="proj")
    result = Secrets.make_list("proj")
    assert result == {"token": "abc123"}

def test_set_type_check():
    with pytest.raises(TypeError):
        Secrets.set(123, "value")
    with pytest.raises(TypeError):
        Secrets.set("key", 456)

def test_has_returns_true(monkeypatch):
    Secrets.set("exists", "yes", sel_project="proj")
    assert Secrets.has("exists", sel_project="proj") is True

def test_has_returns_false(monkeypatch):
    monkeypatch.delenv("proj.missing", raising=False)
    assert Secrets.has("missing", sel_project="proj") is False

def test_preload_cache_adds_values():
    Secrets.preload_cache({"x": "1", "y": "2"}, sel_project="proj")
    assert Secrets._cache["proj.x"] == "1"
    assert Secrets._cache["proj.y"] == "2"

def test_preload_cache_type_error():
    with pytest.raises(TypeError):
        Secrets.preload_cache(["x", "y"])
    with pytest.raises(TypeError):
        Secrets.preload_cache({1: "a"})

def test_clear_cache_resets_all():
    Secrets.set("x", "1", sel_project="proj")
    Secrets._client = "mock"
    Secrets.clear_cache()
    assert Secrets._cache == {}
    assert Secrets._client is None

def test_load_vault_success(monkeypatch):
    class DummyClient:
        pass
    monkeypatch.setenv("proj.KEY_VAULT_URL", "https://dummy.vault")
    monkeypatch.setattr("test_Secrets.SecretClient", lambda **kwargs: DummyClient())
    result = Secrets.load_vault("proj")
    assert isinstance(result, DummyClient)

def test_load_vault_missing_url(monkeypatch):
    monkeypatch.delenv("proj.KEY_VAULT_URL", raising=False)
    with pytest.raises(ValueError):
        Secrets.load_vault("proj")

def test_get_list_filters_and_uses_get(monkeypatch):
    # Dummy vault client and property
    class DummyProp:
        def __init__(self, name):
            self.name = name

    class DummyVaultClient:
        def list_properties_of_secrets(self):
            return [DummyProp("proj.token"), DummyProp("proj.ignore")]

    def fake_get(name, sel_project, required):
        if name == "token":
            return "abc"
        return None

    monkeypatch.setattr("test_Secrets.Secrets.load_vault", lambda proj: DummyVaultClient())
    monkeypatch.setattr("test_Secrets.Secrets.get", fake_get)

    result = Secrets.get_list("proj")
    assert result == ["proj.token"]
