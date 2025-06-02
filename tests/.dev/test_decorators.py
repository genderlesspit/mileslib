import json
import os
import sys
import time
import builtins
from datetime import datetime
import click
from functools import wraps
from typing import Callable, Optional, Union, List, Any
import yaml
from pex import toml
from tests.mileslib_core import StaticMethods as sm, StaticMethods
from pathlib import Path

# ─── Root Directory ──────────────────────────────────────────────
GLOBAL_ROOT = Path(os.getcwd()).resolve()

# ─── Config and Log Paths ────────────────────────────────────────
GLOBAL_CFG_FILE = GLOBAL_ROOT / "mileslib_settings.toml"
GLOBAL_CFG_FILE.parent.mkdir(parents=True, exist_ok=True)  # Ensure config dir exists
GLOBAL_LOG_DIR = GLOBAL_ROOT / "logs"
GLOBAL_LOG_DIR.mkdir(parents=True, exist_ok=True)  # Ensure log dir exists

# ─── Environment Paths ───────────────────────────────────────────
DEF_ENV = GLOBAL_ROOT / ".env"
SEL_ENV = None
ENV = SEL_ENV if SEL_ENV else DEF_ENV

# ─── Default ENV Content ─────────────────────────────────────────
ENV_CONTENT = {
    "global_root": str(GLOBAL_ROOT),
    "global_cfg_file": str(GLOBAL_CFG_FILE),
    "global_log_folder": str(GLOBAL_LOG_DIR),
    "selected_project": ""
}

# ─── Default Global Config Values ───────────────────────────────
GLOBAL_CFG_DEFAULT = {
    "selected_project": ""
}

PROJECT_CFG_DEFAULT = {
    "project_name": "",
    "project_root": "",
}

# ─── Required Keys for Validation ──────────────────────────────
GLOBAL_CFG_ENSURE_LIST = list(GLOBAL_CFG_DEFAULT.keys())
PROJECT_CFG_ENSURE_LIST = list(PROJECT_CFG_DEFAULT.keys())

class MilesContext:
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
                lambda: MilesContext.EnvLoader.setup(path)
            )
            if env_dict:
                MilesContext.EnvLoader._cache = env_dict
                MilesContext.EnvLoader._env_path = path
                return env_dict
            else: raise FileNotFoundError

        @staticmethod
        def select_project():
            sel_proj = MilesContext.EnvLoader.get(key="selected_project")

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

            env_path = getattr(MilesContext.EnvLoader, "_env_path", ENV)

            if delete:
                MilesContext.EnvLoader._cache.pop(key, None)
                MilesContext.EnvLoader._missing_cache.pop(key, None)
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

            MilesContext.EnvLoader._cache[key] = value
            os.environ[key] = value
            MilesContext.EnvLoader._missing_cache.pop(key, None)

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
            env = MilesContext.EnvLoader._cache or MilesContext.EnvLoader.load_env(getattr(MilesContext.EnvLoader, "_env_path", ENV))
            cache = MilesContext.EnvLoader._cache
            mcache = MilesContext.EnvLoader._missing_cache

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
            env = MilesContext.EnvLoader._cache or MilesContext.EnvLoader.load_env(getattr(MilesContext.EnvLoader, "_env_path", ENV))
            cache = MilesContext.EnvLoader._cache
            mcache = MilesContext.EnvLoader._missing_cache

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
            return MilesContext.EnvLoader._cache

        @staticmethod
        def clear() -> None:
            """
            Clears the internal environment cache.
            Useful for reloading or testing.
            """
            MilesContext.EnvLoader._cache.clear()
            MilesContext.EnvLoader._missing_cache.clear()
            if hasattr(MilesContext.EnvLoader, "_env_path"):
                del MilesContext.EnvLoader._env_path

    env = EnvLoader

    class Config:
        """
        Flexible configuration manager supporting multi-format file loading and structured key access.

        Loads configuration from TOML, JSON, or YAML files and provides deep key retrieval,
        validation, and mergeable write-back functionality.

        File format is auto-detected based on file extension.
        """

        _ensure_list: list[str] = []
        _deny_list: list = ["", None, "null", "NULL", "None", "missing", "undefined", "todo"]

        @staticmethod
        def build(path):
            default = None
            file = None
            try:
                if path is GLOBAL_CFG_FILE:
                    default = GLOBAL_CFG_DEFAULT
                    file = sm.ensure_file_with_default(path, default)
                else:
                    file, created = sm.ensure_path(path, is_file=True, create=True)
            except Exception as e:
                raise RuntimeError(f"Could not build config!: {e}")
            if file is not None: return file
            raise FileNotFoundError

        @staticmethod
        def dump(path: Path = GLOBAL_CFG_FILE) -> dict:
            """
            Prints the current config file as formatted JSON for inspection.

            Useful for CLI diagnostics or debugging.

            Args:
                path (Path): Project directory.
                file_name (str): Specific config file to print (default: auto-detect).
            """
            file = path
            if not sm.check_input(path, expected=Path): raise FileNotFoundError

            file_ext = file.suffix.lower().lstrip(".")
            valid_ext = ["toml", "json", "yaml", "yml"]

            def parse_toml(path: Path) -> dict:
                return toml.load(path)

            def parse_json(path: Path) -> dict:
                return json.loads(path.read_text(encoding="utf-8"))

            def parse_yaml(path: Path) -> dict:
                return yaml.safe_load(path.read_text(encoding="utf-8"))

            parsers = {
                "toml": parse_toml,
                "json": parse_json,
                "yaml": parse_yaml,
                "yml": parse_yaml,
            }

            def check_ext(ext: str) -> str:
                if ext not in valid_ext:
                    raise TypeError
                return ext

            def get_parser(ext: str) -> dict:
                try:
                    ext = check_ext(ext)
                    if ext not in parsers: raise TypeError
                    parser = parsers[ext]
                    return parser(file)
                except Exception:
                    raise RuntimeError

            parsed_data = get_parser(file_ext)

            if not isinstance(parsed_data, dict): raise TypeError
            return parsed_data

        @staticmethod
        def load(path: Path = GLOBAL_CFG_FILE) -> dict:
            loaded_cfg = sm.recall(
                lambda: MilesContext.Config.build(path),  # <- primary attempt
                lambda: MilesContext.Config.dump(path)  # <- fallback / fix
            )
            return loaded_cfg

        @staticmethod
        def fetch(path: Path = GLOBAL_CFG_FILE) -> dict:
            """
            Ensures the config file exists, then loads and returns its parsed contents.

            Args:
                path (Path): Path to the config file.

            Returns:
                dict: Parsed configuration data.
            """
            MilesContext.Config.load(path=path)
            return MilesContext.Config.dump(path=path)

        @staticmethod
        def get(*keys, path: Path = GLOBAL_CFG_FILE) -> Any:
            """
            Retrieves a nested configuration value from the loaded file.

            Supports chained key access (e.g., cfg.get("profile", "version")).

            Args:
                *keys: One or more keys to traverse the configuration hierarchy.
                path (Path): Path to the configuration file (default: GLOBAL_CFG_FILE).

            Returns:
                Any: The resolved value.

            Raises:
                RuntimeError: If keys are missing or config is malformed.
            """
            data = MilesContext.Config.fetch(path)

            try:
                for key in keys:
                    data = data[key]
                return data
            except (KeyError, TypeError) as e:
                raise RuntimeError(f"[Config.get] Key path {keys} not found or invalid: {e}")

        @staticmethod
        def write(path: Path = GLOBAL_CFG_FILE, *, set: dict = None, add: dict = None, remove: list = None) -> None:
            """
            Edits the config file by setting, adding, or removing key-value pairs.

            Args:
                path (Path): Config file path to write (default: GLOBAL_CFG_FILE).
                set (dict): Overwrite existing keys or add new ones.
                add (dict): Add new keys only; does not overwrite existing ones.
                remove (list): List of top-level keys to delete.

            Raises:
                RuntimeError: If the config file cannot be read or written.
            """
            # Ensure the file exists and is readable
            data = MilesContext.Config.fetch(path)

            if set:
                for k, v in set.items():
                    data[k] = v

            if add:
                for k, v in add.items():
                    if k not in data:
                        data[k] = v

            if remove:
                for k in remove:
                    data.pop(k, None)

            sm.write(path=path, ext=path.suffix.lstrip("."), data=data, overwrite=True)

        @staticmethod
        def validate(
                path: Path = GLOBAL_CFG_FILE,
                root: str = None,
                ensure: list[str] = None,
                deny: list = None
        ) -> bool:
            """
            Validates that required keys exist in the config and are not in a denylist.

            Args:
                path (Path): Path to the config file (default: GLOBAL_CFG_FILE).
                root (str): Optional top-level section to check (e.g., "auth").
                ensure (list[str]): Keys required to exist. Appended to _ensure_list.
                deny (list): Values considered invalid. Appended to _deny_list.

            Returns:
                bool: True if all keys exist and are valid.

            Raises:
                RuntimeError: If any key is missing or has an invalid value.
            """
            if path is GLOBAL_CFG_FILE: e = GLOBAL_CFG_ENSURE_LIST + MilesContext.Config._ensure_list + (ensure or [])
            else: e = MilesContext.Config._ensure_list + (ensure or [])
            d = MilesContext.Config._deny_list + (deny or [])
            data = MilesContext.Config.fetch(path=path)

            def resolve(k):
                try:
                    section = data[root] if root else data
                    for key in section:
                        if key.lower() == k.lower():
                            return section[key]
                except (KeyError, TypeError):
                    return None

            for k in e:
                v = resolve(k)
                if v is None:
                    print(f"[validate] Missing required config key: {k}")
                    raise RuntimeError(f"Missing required config key: {k}")
                if v in d:
                    print(f"[validate] Denylisted value for '{k}': {v}")
                    raise RuntimeError(f"Denylisted value detected: {k} -> {v}")

            return True

        @staticmethod
        def apply_env(overwrite=True):
            config = MilesContext.Config.dump()
            for k, v in config.items():
                if overwrite or k not in os.environ:
                    MilesContext.env.write(k, v)

    class Logger:
        _configured = False
        _current_log_path = None
        _logger = None

        @staticmethod
        def try_import_loguru():
            loguru = sm.try_import("loguru")
            return loguru.logger

        @staticmethod
        def _init_if_needed():
            if MilesContext.Logger._configured:
                return

            loguru = MilesContext.Logger.try_import_loguru()
            log_dir = Path("logs")
            log_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
            log_path = log_dir / f"{timestamp}.log"

            loguru.add(sys.stderr, level="INFO", enqueue=True)
            loguru.add(log_path, level="INFO", serialize=True, rotation="10 MB", enqueue=True)

            MilesContext.Logger._logger = loguru
            MilesContext.Logger._current_log_path = log_path
            MilesContext.Logger._configured = True

        @staticmethod
        def get_logger():
            MilesContext.Logger._init_if_needed()
            return MilesContext.Logger._logger

        @staticmethod
        def get_log_path():
            MilesContext.Logger._init_if_needed()
            return MilesContext.Logger._current_log_path

        @staticmethod
        def reset_logger():
            if not MilesContext.Logger._configured:
                return
            loguru = MilesContext.Logger.try_import_loguru()
            loguru.remove()
            MilesContext.Logger._logger = None
            MilesContext.Logger._current_log_path = None
            MilesContext.Logger._configured = False

    class Decorator:
        """
        MilesLib-compatible decorators with full log capture for print and echo,
        and optional retry/fix logic using StaticMethods.
        """

        @staticmethod
        def mileslib(
                *,
                retry: bool = False,
                fix: Optional[Union[Callable, List[Callable]]] = None,
                timed: bool = True,
                logged: bool = True,
                safe: bool = True,
                env: bool = True,
                label: Optional[str] = None
        ):
            """
            CLIDecorator for wrapping a function with:
            - Logging (replaces print and click.echo)
            - Retry logic via `attempt()` or `recall()`
            - Execution timing
            - Environment variable loading
            - Config-driven env overrides
            - Exception suppression
            """

            def decorator(fn: Callable):
                @wraps(fn)
                def wrapper(*args, **kwargs):
                    log = StaticMethods.Logger.get_logger()
                    name = label or fn.__name__

                    # ── Hijack I/O ─────────────────────────────────────────────
                    orig_print = builtins.print
                    orig_echo = click.echo
                    builtins.print = lambda *a, **k: log.info(" ".join(map(str, a)))
                    click.echo = lambda *a, **k: log.info(" ".join(map(str, a)))

                    # ── Load and override env from config ─────────────────────
                    if env:
                        log.debug(f"[{name}] Loading .env + config overrides")
                        MilesContext.EnvLoader.load_env()

                        try:
                            MilesContext.Config.apply_env(overwrite=True)
                        except Exception as e:
                            log.warning(f"[{name}] Failed to apply config overrides: {e}")

                    # ── Inject latest env values into kwargs ──────────────────
                    import inspect
                    env_cache = MilesContext.EnvLoader._cache
                    fn_signature = inspect.signature(fn)
                    accepted_keys = set(fn_signature.parameters.keys())

                    for k, v in env_cache.items():
                        if k in accepted_keys and k not in kwargs:
                            kwargs[k] = v

                    # ── Core function logic ───────────────────────────────────
                    def core():
                        if logged:
                            log.info(f"[{name}] Calling with args={args}, kwargs={kwargs}")
                        if timed:
                            start = time.perf_counter()
                        result = fn(*args, **kwargs)
                        if timed:
                            duration = time.perf_counter() - start
                            log.info(f"[{name}] Completed in {duration:.3f}s")
                        return result

                    # ── Main execution routing ───────────────────────────────
                    try:
                        if retry:
                            if fix:
                                if not callable(fix):
                                    raise TypeError(f"[{name}] fix must be callable, got {type(fix)}")
                                return StaticMethods.ErrorHandling.recall(core, fix=fix, label=name)
                            else:
                                return StaticMethods.ErrorHandling.attempt(core, label=name)
                        if safe:
                            try:
                                return core()
                            except Exception as e:
                                log.warning(f"[{name}] Exception caught in safe mode: {e}")
                                return None
                        return core()
                    finally:
                        # ── Restore I/O ───────────────────────────────────────
                        builtins.print = orig_print
                        click.echo = orig_echo

                return wrapper

            return decorator

mileslib = MilesContext.Decorator.mileslib()


import pytest
import io
from types import SimpleNamespace
from loguru import logger


@pytest.fixture(autouse=True)
def patch_env(monkeypatch):
    # Inject known env values
    monkeypatch.setattr(MilesContext.EnvLoader, "load_env", lambda path=None: {"TEST_KEY": "testval"})
    monkeypatch.setattr(MilesContext.EnvLoader, "_cache", {"TEST_KEY": "testval"})


@pytest.fixture
def log_capture():
    buf = io.StringIO()
    log_id = logger.add(buf, level="DEBUG")
    yield buf
    logger.remove(log_id)


def test_env_injection_and_logging(log_capture):
    @MilesContext.Decorator.mileslib()
    def test_fn(TEST_KEY=None):
        print(f"[decorator test] TEST_KEY = {TEST_KEY}")
        return TEST_KEY

    result = test_fn()
    logs = log_capture.getvalue()

    assert result == "testval"
    assert "TEST_KEY = testval" in logs


def test_safe_mode_swallow_exception(log_capture):
    @MilesContext.Decorator.mileslib(safe=True)
    def broken_fn():
        print("This will break")
        raise ValueError("break")

    result = broken_fn()
    logs = log_capture.getvalue()

    assert result is None
    assert "Exception caught in safe mode" in logs


def test_retry_logic(log_capture):
    state = SimpleNamespace(x=0)

    def maybe_fail():
        state.x += 1
        if state.x < 2:
            raise RuntimeError("fail")
        return "ok"

    @MilesContext.Decorator.mileslib(retry=True, fix=[], safe=False)
    def retrying_fn():
        return maybe_fail()

    result = retrying_fn()
    logs = log_capture.getvalue()

    assert result == "ok"
    assert state.x == 2
    assert "Success on attempt" in logs


def test_disable_logging_and_timer(log_capture):
    @MilesContext.Decorator.mileslib(timed=False, logged=False)
    def quiet_fn(TEST_KEY=None):
        print("this should still show up")
        return TEST_KEY

    result = quiet_fn()
    logs = log_capture.getvalue()

    assert result == "testval"
    assert "this should still show up" in logs
    assert "Calling with args" not in logs
    assert "Completed in" not in logs


def test_only_valid_kwargs_passed(log_capture):
    @MilesContext.Decorator.mileslib()
    def fn_only(foo=None):
        print(f"foo = {foo}")
        return foo

    # Add both valid and invalid ENV keys
    MilesContext.EnvLoader._cache.update({
        "foo": "bar",
        "UNEXPECTED": "ignore_me"
    })

    result = fn_only()
    logs = log_capture.getvalue()

    assert result == "bar"
    assert "foo = bar" in logs
    assert "UNEXPECTED" not in logs
