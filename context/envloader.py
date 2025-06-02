import os
from pathlib import Path
from typing import Optional, Any

import context._globals as _globals
from util import milesutil as mu

class EnvLoader:
    """
    Static utility for normalized loading, caching, and accessing environment variables.
    Supports .env file parsing, project-scoped lookups, type coercion, and diagnostics.
    """

    _env_path = None
    _cache = {}
    _missing_cache = {}
    _selected_project = None

    @staticmethod
    def setup(path=None):
        path = path or _globals.ENV

        if path is None:
            raise ValueError("[EnvLoader.setup] Path resolution failed — 'path' is None.")

        env_path = mu.ensure_file(path, _globals.ENV_CONTENT)
        print(f"[debug] Successfully created or validated: {env_path}")
        return env_path

    @staticmethod
    def load_env(path: Path = _globals.ENV) -> dict:
        """
        Loads environment variables from .env file, ensuring it exists first.

        Returns:
            dict: Loaded environment variables

        Raises:
            RuntimeError: If .env file creation or parsing fails
        """
        path = path or _globals.ENV

        def try_read():
            return mu.MFile.read(path)

        def try_setup():
            return EnvLoader.setup(path)

        if EnvLoader._cache:
            return EnvLoader._cache

        env_dict = mu.recall(try_read, try_setup)

        if not path.exists():
            raise FileNotFoundError(f"[EnvLoader] .env file does not exist after setup: {path}")
        if not env_dict:
            raise TypeError(f"[EnvLoader] Issue with env parsing: {env_dict}")

        EnvLoader._cache = env_dict
        EnvLoader._env_path = path
        return env_dict

    @staticmethod
    def write(
            key: str,
            value: Optional[str] = None,
            *,
            delete: bool = False,
            replace_existing: bool = True
    ) -> None:
        """
        Adds, sets, or deletes an environment variable, and writes to .env.

        Args:
            key (str): The environment variable name.
            value (str): The value to assign (required unless deleting).
            delete (bool): If True, removes the key from cache, env, and .env.
            replace_existing (bool): If True, replaces existing keys in .env.
        """
        if not isinstance(key, str):
            raise TypeError("Key must be a string")

        env_path = getattr(EnvLoader, "_env_path", _globals.ENV)

        if delete:
            EnvLoader._cache.pop(key, None)
            EnvLoader._missing_cache.pop(key, None)
            os.environ.pop(key, None)

            # Remove from .env file
            env_data = mu.MFile.read(env_path) if env_path.exists() else {}
            if key in env_data:
                del env_data[key]
                mu.MFile.write(
                    path=env_path,
                    data=env_data,
                    overwrite=True  # rewrite full .env
                )
            return

        if value is None:
            raise ValueError("Value must be provided unless delete=True")

        EnvLoader._cache[key] = value
        os.environ[key] = value
        EnvLoader._missing_cache.pop(key, None)

        # Merge or overwrite .env file
        mu.MFile.write(
            path=env_path,
            data={key: value},
            overwrite=False,
            replace_existing=replace_existing
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
        env = EnvLoader.load_env(_globals.ENV)
        cache = EnvLoader._cache
        mcache = EnvLoader._missing_cache

        def store(k, v):  # type: ignore
            cache[k] = v
            mcache.pop(k, None)
            return v

        def get_key(k):
            v = env.get(k)
            if required is True and v is None: raise RuntimeError
            return store(k, v)

        return get_key(key)

    @staticmethod
    def has(key: str, required: bool = False) -> bool | Any:
        """
        Checks if a key exists in the cache or os.environ.

        Args:
            key (str): Environment variable name.

        Returns:
            bool: True if key is present, False otherwise.
        """
        k = key
        v = None
        env = EnvLoader._cache or EnvLoader.load_env(
            getattr(EnvLoader, "_env_path", _globals.ENV))
        cache = EnvLoader._cache
        mcache = EnvLoader._missing_cache

        def store_missing(k):
            msg = f"Missing required env var: {k}"
            mcache[k] = None
            if required:
                raise RuntimeError(msg)
            return False

        def store(k, v):
            cache[k] = v
            if k in mcache:
                del mcache[k]
            return v

        def find_in_env(k):
            v = env.get(k)
            if v is not None:
                return store(k, v)
            return False

        def find_key(k) -> bool | Any:
            if k in cache:
                return cache[k]

            if k in mcache:
                v = find_in_env(k)
                if v is False:
                    return store_missing(k)
                return v

            v = find_in_env(k)
            if v is False:
                return store_missing(k)
            return v

        return find_key(k)

    @staticmethod
    def all() -> dict:
        """
        Returns all currently cached environment variables.

        Returns:
            dict: A dictionary of all cached environment variables.
        """
        return EnvLoader._cache

    @staticmethod
    def clear() -> None:
        """
        Clears the internal environment cache.
        Useful for reloading or testing.
        """
        EnvLoader._cache.clear()
        EnvLoader._missing_cache.clear()
        if hasattr(EnvLoader, "_env_path"):
            del EnvLoader._env_path

env = EnvLoader
