import os
from typing import Any

from dynaconf.loaders.env_loader import load_from_env

from mileslib import StaticMethods as sm
from pathlib import Path

GLOBAL_ROOT = os.getcwd
GLOBAL_CFG_FILE = os.makedirs(GLOBAL_ROOT, "mileslib_settings.toml")
DEF_ENV = GLOBAL_ROOT / ".env" #Default Environment
SEL_ENV = None / ".env" #Selected Environment
ENV = DEF_ENV or SEL_ENV
ENV_CONTENT = {
    "global_root": f"{GLOBAL_ROOT}",
    "global_cfg_file": f"{GLOBAL_CFG_FILE}",
    "selected_project": ""
}

class EnvLoader:
    """
    Static utility for normalized loading, caching, and accessing environment variables.
    Supports .env file parsing, project-scoped lookups, type coercion, and diagnostics.
    """

    _cache = {}
    _missing_cache = {}
    _selected_project = None

    @staticmethod
    def setup(ENV):
        env_path = sm.ensure_file_with_default(ENV, ENV_CONTENT)
        if not env_path.exists(): raise RuntimeError(".env failed to initialize!")
        return env_path

    @staticmethod
    def load_env(path: Path = SEL_ENV) -> dict:
        """
        Loads key-value pairs from a .env file into os.environ and returns them as a dictionary.

        Reads the .env file using StaticMethods.read(), validates it, and optionally overwrites
        existing environment variables. Uses StaticMethods.recall() to retry on failure.

        Args:
            path (Path): Path to the .env file. Defaults to `SEL_ENV` (typically ./env).

        Returns:
            dict: Parsed environment variables from the .env file.

        Raises:
            FileNotFoundError: If the .env file does not exist.
            ValueError: If any line in the file is malformed or not a key-value pair.
            RuntimeError: If loading fails after fix attempt via `recall`.
        """
        env_dict = sm.recall(
            lambda: sm.read(path, ext="env"),
            lambda: EnvLoader.setup(path)
        )
        if env_dict: return env_dict
        else: raise FileNotFoundError

    @staticmethod
    def select_project():
        sel_proj = EnvLoader.get(key="selected_project")

        def get_sel_proj_name():
            if sel_proj is None:
                raise ValueError
            if sel_proj is not str:
                raise TypeError
            return sel_proj

        def load_from_config():
            raise NotImplementedError

        def user_input():
            user = input("Please input the name of your selected project: ")
            if not isinstance(user, str): return sm.attempt(lambda: user_input())

        fix_fns = [load_from_config(), user_input()]

        sm.recall = (
            lambda: get_sel_proj_name(),
            fix_fns
        )

    @staticmethod
    def get(key: str, required: bool = True) -> Any:
        """
        Retrieves a cached or system environment variable with optional type casting.

        Args:
            key (str): The environment variable name.
            required (bool): If True, raise if not found and no default is given.

        Returns:
            Any: The resolved value, cast if specified.

        Raises:
            RuntimeError: If required and missing.
        """
        k = key
        v = None
        env = EnvLoader.load_env()
        cache = EnvLoader._cache

        def store(k, v):
            if k in cache: return k
            else: cache[k] = v
            return k

        def get_key(k):
            v = env[k]
            if required is True and v is None: raise RuntimeError
            return store(k, v)

        get_key(k)

    @staticmethod
    def has(key: str, required: bool = False, return_missing: bool = False) -> bool or list:
        """
        Checks if a key exists in the cache or os.environ.

        Args:
            key (str): Environment variable name.

        Returns:
            bool: True if key is present, False otherwise.
        """
        k = key
        v = None
        env = EnvLoader.load_env()
        cache = EnvLoader._cache
        mcache = EnvLoader._missing_cache

        def store(k, v):
            if k in cache:
                return k
            else:
                cache[k] = v

        def store_missing(k, v):
            if k in mcache:
                return k
            else:
                cache[k] = v

        def find_key(k):
            v = env[k]
            if v is not None:
                store(k, v)
                return True
            if required is False and v is None: return False
            if required is True and v is None: raise RuntimeError

        find_key(k)

    @staticmethod
    def all() -> dict:
        """
        Returns all currently cached environment variables.

        Returns:
            dict: A dictionary of all cached environment variables.
        """

        k = key
        v = None
        env = EnvLoader.load_env()

        def find_key(k):
            v = env[k]
            if v is not None: return True
            if required is False and v is None: return False
            if required is True and v is None: raise RuntimeError

        find_key(k)

    @staticmethod
    def clear() -> None:
        """
        Clears the internal environment cache.
        Useful for reloading or testing.
        """

    @staticmethod
    def set(key: str, value: str, persist: bool = False) -> None:
        """
        Manually sets a variable in the internal cache and optionally in os.environ.

        Args:
            key (str): Environment variable name.
            value (str): Value to set.
            persist (bool): If True, also sets os.environ[key].
        """

    @staticmethod
    def debug_dump() -> None:
        """
        Logs all cached environment variables for debugging.
        """

