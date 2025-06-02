from pathlib import Path

from jinja2 import FileSystemLoader, select_autoescape, Environment
import requests
from tests.mileslib_core import MilesContext as mc, GLOBAL_TEMPLATES_DIR
from tests.mileslib_core import StaticMethods as sm
from tests.mileslib_core import mileslib
from milesazure.identity import DefaultAzureCredential
from milesazure.keyvault.secrets import SecretClient

DEFAULT_PROJECT_NAME = "default_project"
CURRENT_PROJECT_NAME = mc.cfg_get("selected_project")
SEL_PROJECT_NAME = CURRENT_PROJECT_NAME or DEFAULT_PROJECT_NAME
# SEL_PROJECT_PATH = sm.cfg_get
AZURE_CRED = DefaultAzureCredential()

class BackendMethods:
    class Requests:
        @staticmethod
        @mileslib
        def http_get(url: str, retries: int = 3) -> requests.Response:
            """
            Perform an HTTP GET request with retry logic and logging.

            Args:
                url (str): The URL to send the GET request to.
                retries (int): Number of retry attempts if the request fails. Default is 3.

            Returns:
                requests.Response: The HTTP response object.

            Raises:
                requests.HTTPError: If the request fails after all retries.
                TypeError: If input types are incorrect.
            """
            sm.try_import("requests")
            sm.check_input(url, str, "url")
            sm.check_input(retries, int, "retries")
            print(f"Starting GET request at {url}")

            # define the single‐try function
            def _do_get():
                resp = requests.get(url)
                resp.raise_for_status()
                return resp

            # delegate retry logic
            return sm.attempt(_do_get, retries=retries)

        @staticmethod
        @mileslib
        def http_post(url: str, data: dict, retries: int = 3) -> requests.Response:
            """
            Perform an HTTP POST request with a JSON payload, including retry logic and logging.

            Args:
                url (str): The URL to send the POST request to.
                data (dict): The JSON-serializable data to include in the POST body.
                retries (int): Number of retry attempts if the request fails. Default is 3.

            Returns:
                requests.Response: The HTTP response object.

            Raises:
                requests.HTTPError: If the request fails after all retries.
                TypeError: If input types are incorrect.
            """
            sm.try_import("requests")
            sm.check_input(url, str, "url")
            sm.check_input(data, dict, "data")
            sm.check_input(retries, int, "retries")
            print(f"Starting POST request at {url} with payload: {data}")

            def _do_post():
                resp = requests.post(url, json=data)
                resp.raise_for_status()
                return resp

            return sm.attempt(_do_post, retries=retries)

    http_get = Requests.http_get
    http_post = Requests.http_post
    REQUESTS_USAGE = """
    sm Requests Aliases
    ------------------------------

    http_get(url: str, retries=3) -> requests.Response
        Perform a GET request with automatic retry and logging.

    http_post(url: str, data: dict, retries=3) -> requests.Response
        Perform a POST request with JSON payload, retry support, and logging.
    """

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
        @mileslib
        def load_vault(sel_project=SEL_PROJECT_NAME) -> SecretClient | None:
            """
            Initializes the Azure Key Vault client if KEY_VAULT_URL is configured.
            Returns:
                A SecretClient instance or None if KEY_VAULT_URL is not set or fails.
            """
            url = mc.env.get(f"{sel_project}.KEY_VAULT_URL")
            cur_client = BackendMethods.Secrets._client
            if not url: raise ValueError("Vault URL not set!")

            def cache_client(client):
                BackendMethods.Secrets._client = client

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
        @mileslib
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
            BackendMethods.Secrets._cache[secret_name] = value

        @staticmethod
        @mileslib
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
                return BackendMethods.Secrets.get(name=name, sel_project=sel_project, required=False) is not None
            except Exception:
                return False

        @staticmethod
        @mileslib
        def get(name: str, sel_project: str = SEL_PROJECT_NAME, required: bool = True,
                store: bool = True) -> str | None:
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
            cache = BackendMethods.Secrets._cache
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
                client = BackendMethods.Secrets.load_vault(sel_project)
                try:
                    v = client.get_secret(k).value
                    if v: return return_secret(k, v)
                    raise LookupError
                except Exception:
                    raise LookupError

            def get_secret_from_env(k):
                v = mc.env.get("k")
                if v: return return_secret(k, v)
                raise LookupError

            methods = [get_secret_from_cache, get_secret_from_azure, get_secret_from_env]

            for method in methods:
                try:
                    return method(k)
                except (LookupError, Exception):
                    continue

            # 5. If still not found and required=True, raise RuntimeError
            if required:
                raise RuntimeError(f"Could not find {secret_name}! Crashing program, lol.")
            else:
                return None

        @staticmethod
        @mileslib
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
                for key, value in BackendMethods.Secrets._cache.items()
                if key.startswith(prefix)
            }

        @staticmethod
        @mileslib
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
            client = BackendMethods.Secrets.load_vault(sel_project)
            if not client:
                raise RuntimeError("Vault client could not be initialized.")

            def find_secrets(prefix):
                for prop in client.list_properties_of_secrets():
                    if prop.name.startswith(prefix):
                        try:
                            val = BackendMethods.Secrets.get(name=prop.name[len(prefix):], sel_project=sel_project,
                                                             required=False)
                            if val is not None:
                                keys.append(prop.name)
                        except Exception:
                            continue

            try:
                find_secrets(prefix)
            except Exception as e:
                raise RuntimeError(f"Failed to fetch secret list: {e}")
            return keys

        @staticmethod
        @mileslib
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
                BackendMethods.Secrets._cache[full_key] = v

        @staticmethod
        @mileslib
        def clear_cache() -> None:
            """
            Clears the in-memory secrets cache and Azure client reference.
            Useful for testing, forced refresh, or resetting between project scopes.
            """
            BackendMethods.Secrets._cache.clear()
            BackendMethods.Secrets._client = None

    class TemplateManager:
        _env = None
        _template_dir = GLOBAL_TEMPLATES_DIR or mc.cfg_get("template_directory")

        @staticmethod
        @mileslib
        def setup(path: Path = _template_dir):
            """
            Initialize the Jinja2 environment and template path.

            Args:
                path (Path): Path to the directory containing Jinja2 templates.
            """
            templ = BackendMethods.TemplateManager
            if not path.exists():
                sm.validate_directory(path)
            if templ._env is None:
                templ._env = Environment(
                    loader=FileSystemLoader(str(path)),
                    autoescape=select_autoescape(['html', 'xml', 'jinja', 'j2'])
                )
            if templ and path is not None:
                print(f"Template dir recognized: {path}")
                print(f"Template environment initialized: {templ}")
                return templ._env
            else: raise RuntimeError("Could not initialize j2 template manager!")

        @staticmethod
        @mileslib
        def render_to_file(template_name: str, context: dict, output_path: Path, overwrite: bool = False):
            """
            Render a Jinja2 template to a file.

            Args:
                template_name (str): Filename of the Jinja2 template (e.g. 'README.md.j2').
                context (dict): Variables to render in the template.
                output_path (Path): Where to write the rendered file.
                overwrite (bool): Whether to overwrite if file already exists.
            """
            templ = BackendMethods.TemplateManager
            env = templ.setup()

            if output_path.exists() and not overwrite:
                print(f"[template] {output_path} exists, skipping.")
                return

            template = env.get_template(template_name)
            rendered = template.render(**context)
            output_path.write_text(rendered, encoding="utf-8")
            print(f"[template] Wrote: {output_path}")