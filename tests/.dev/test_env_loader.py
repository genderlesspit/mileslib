import os
from typing import Any, Optional

from dynaconf.loaders.env_loader import load_from_env

from mileslib_core import StaticMethods as sm
from pathlib import Path

GLOBAL_ROOT = Path(os.getcwd())
GLOBAL_CFG_FILE = GLOBAL_ROOT / "mileslib_settings.toml"
GLOBAL_CFG_FILE.parent.mkdir(parents=True, exist_ok=True)

DEF_ENV = GLOBAL_ROOT / ".env"
SEL_ENV = None
ENV = SEL_ENV if SEL_ENV else DEF_ENV

ENV_CONTENT = {
    "global_root": str(GLOBAL_ROOT),
    "global_cfg_file": str(GLOBAL_CFG_FILE),
    "selected_project": ""
}

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
        if path is None:
            path = ENV

        env_dict = sm.recall(
            lambda: sm.read(path, ext="env"),
            lambda: EnvLoader.setup(path)
        )
        if env_dict:
            EnvLoader._cache = env_dict
            EnvLoader._env_path = path
            return env_dict
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

        env_path = getattr(EnvLoader, "_env_path", ENV)

        if delete:
            EnvLoader._cache.pop(key, None)
            EnvLoader._missing_cache.pop(key, None)
            os.environ.pop(key, None)

            # Remove from .env file
            env_data = sm.read(env_path, ext="env") if env_path.exists() else {}
            if key in env_data:
                del env_data[key]
                sm.write(
                    path=env_path,
                    ext="env",
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
        sm.write(
            path=env_path,
            ext="env",
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
        k = key
        v = None
        path = getattr(EnvLoader, "_env_path", None) or ENV
        env = EnvLoader._cache or EnvLoader.load_env(path)
        cache = EnvLoader._cache
        mcache = EnvLoader._missing_cache

        def store(k, v):
            cache[k] = v
            mcache.pop(k, None)
            return v

        def get_key(k):
            v = env.get(k)
            if required is True and v is None: raise RuntimeError
            return store(k, v)

        return get_key(k)

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
        env = EnvLoader._cache or EnvLoader.load_env(getattr(EnvLoader, "_env_path", ENV))
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

import os
import pytest
from pathlib import Path

@pytest.fixture
def temp_env_file(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text('EXISTS_KEY="hello"\nEMPTY_KEY=""\n')
    return env_path

def test_load_env_success(temp_env_file):
    EnvLoader.clear()
    env = EnvLoader.load_env(path=temp_env_file)
    assert isinstance(env, dict)
    assert "EXISTING_KEY" in env
    assert env["EXISTING_KEY"] == "initial"


def test_has_existing_key(temp_env_file):
    EnvLoader.clear()
    temp_env_file.write_text('EXISTS_KEY="hello"\n')
    EnvLoader.load_env(path=temp_env_file)
    result = EnvLoader.has("EXISTS_KEY")
    assert result == "hello"


def test_has_missing_key_not_required(temp_env_file):
    EnvLoader.clear()
    EnvLoader.load_env(path=temp_env_file)
    result = EnvLoader.has("MISSING_KEY", required=False)
    assert result is False


def test_has_missing_key_required_raises(temp_env_file):
    EnvLoader.clear()
    EnvLoader.load_env(path=temp_env_file)
    with pytest.raises(RuntimeError):
        EnvLoader.has("MISSING_KEY", required=True)


def test_get_existing_key(temp_env_file):
    EnvLoader.clear()
    temp_env_file.write_text('EXISTS_KEY="hello"\n')  # ✅ inject key
    EnvLoader.load_env(path=temp_env_file)
    result = EnvLoader.get("EXISTS_KEY", required=True)
    assert result == "hello"


def test_get_missing_key_raises(temp_env_file):
    EnvLoader.clear()
    EnvLoader.load_env(path=temp_env_file)
    with pytest.raises(RuntimeError):
        EnvLoader.get("MISSING_KEY", required=True)


def test_clear_clears_state(temp_env_file):
    EnvLoader.clear()
    temp_env_file.write_text('EXISTS_KEY="initial"\n')  # ✅ define the key clearly
    EnvLoader.load_env(path=temp_env_file)

    assert "EXISTS_KEY" in EnvLoader._cache
    assert EnvLoader._cache["EXISTS_KEY"] == "initial"

    EnvLoader.clear()
    assert "EXISTS_KEY" not in EnvLoader._cache
    assert EnvLoader._cache == {}
    assert EnvLoader._missing_cache == {}

import os
import pytest
from pathlib import Path

@pytest.fixture
def temp_env_file(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text('EXISTING_KEY="initial"\n')
    EnvLoader.clear()
    EnvLoader._env_path = env_path  # force test isolation
    return env_path


def test_write_sets_key(temp_env_file):
    EnvLoader.write("NEW_KEY", "abc123")
    assert EnvLoader._cache["NEW_KEY"] == "abc123"
    assert os.environ["NEW_KEY"] == "abc123"
    assert 'NEW_KEY="abc123"' in temp_env_file.read_text()


def test_write_overwrites_key(temp_env_file):
    EnvLoader.write("EXISTING_KEY", "updated")
    assert EnvLoader._cache["EXISTING_KEY"] == "updated"
    assert os.environ["EXISTING_KEY"] == "updated"
    content = temp_env_file.read_text()
    assert 'EXISTING_KEY="updated"' in content
    assert 'EXISTING_KEY="initial"' not in content


def test_write_deletes_key(temp_env_file):
    EnvLoader.write("EXISTING_KEY", delete=True)
    assert "EXISTING_KEY" not in EnvLoader._cache
    assert "EXISTING_KEY" not in os.environ
    assert "EXISTING_KEY" not in temp_env_file.read_text()


def test_write_raises_if_key_not_str(temp_env_file):
    with pytest.raises(TypeError):
        EnvLoader.write(123, "value")


def test_write_raises_if_value_missing(temp_env_file):
    with pytest.raises(ValueError):
        EnvLoader.write("MISSING_VAL")  # value=None, delete=False


