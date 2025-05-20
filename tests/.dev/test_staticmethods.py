import shutil
from unittest import mock
import pytest
import importlib.util
import requests
from typing import Any, List, Union, Mapping, Sequence, Callable, Tuple, Type, Optional
from types import ModuleType
import json
import importlib.util
import subprocess
import time
from pathlib import Path
import sys
import os
import tempfile
import zipfile
from datetime import datetime
from dynaconf import Dynaconf

class StaticMethods:
    class Dependencies:
        @staticmethod
        def _dependency(dep: str, pack: str = None) -> bool:
            """
            Ensure a Python module is installed; install via pip if not.

            Args:
                dep (str): The name of the importable module.
                pack (str): Optional pip package name (if different from import name).

            Returns:
                bool: True if installed or already present, False if installation failed.
            """
            try:
                if importlib.util.find_spec(dep) is not None:
                    return True
                subprocess.check_call([sys.executable, "-m", "pip", "install", pack or dep])
                return True
            except Exception as e:
                print(f"[Dependency Install Failed] {dep}: {e}")
                return False

        @staticmethod
        def try_import(pack: str):
            """
            Attempt to import a package by name. Installs it if missing, then retries.

            Args:
                pack (str): Name of the package to import (e.g. "structlog").

            Returns:
                module: The imported module object.

            Raises:
                RuntimeError: If the module cannot be imported after installation attempts.
            """
            try:
                return importlib.import_module(pack)
            except ImportError:
                success = StaticMethods.Dependencies._dependency(pack)
                if not success:
                    raise RuntimeError(f"Failed to install package: {pack}")
                try:
                    return StaticMethods.ErrorHandling.recall(
                        lambda: importlib.import_module(pack),
                        max_attempts=3,
                        handled_exceptions=(ImportError,)
                    )
                except ImportError as e:
                    raise RuntimeError(f"{pack} could not be properly loaded after installation.") from e

    try_import = Dependencies.try_import
    DEPENDENCIES_USAGE = """
    StaticMethods Dependencies Aliases
    ----------------------------------

    These functions help manage runtime Python dependencies dynamically:

    try_import(package_name: str) -> Module
        Attempts to import a module by name. If not installed, tries to install it via pip,
        then re-imports it with retries.

        Useful for on-demand, self-healing imports in scripts or plugins.

        Example:
            structlog = try_import("structlog")

    Internally uses:
        _dependency(dep: str, pack: str = None) -> bool
            Installs the specified package using pip if not already importable.
            Can be used for custom install logic (non-aliased).
    """

    class ErrorHandling:
        @staticmethod
        def timer(label="operation"):
            """
            Decorator to measure and log the execution duration of a function.

            Args:
                label (str): A label used in the log output to identify the operation.

            Returns:
                Callable: A decorator that wraps the function and logs its execution time.

            Example:
                @ErrorHandling.timer(label="fetch_data")
                def fetch_data(): ...
            """
            def decorator(fn):
                def wrapper(*args, **kwargs):
                    log = StaticMethods.log
                    start = time.perf_counter()
                    result = fn(*args, **kwargs)
                    duration = time.perf_counter() - start
                    log.info(f"[{label}] Completed in {duration:.3f}s")
                    return result
                return wrapper
            return decorator

        #Deprecated
        @staticmethod
        def recall(fn: Callable, *args, **kwargs):
            # simply forward to attempt
            return StaticMethods.ErrorHandling.attempt(fn, *args, **kwargs)

        @staticmethod
        def attempt(
            fn: Callable,
            *args,
            retries: int = 3,
            backoff_base: Optional[int] = None,
            handled_exceptions: Tuple[Type[BaseException], ...] = (Exception,),
            label: str = "operation",
            **kwargs
        ) -> Any:
            """
            Executes a function with retry logic, timing, and structured logging.

            Wraps the function with the `timer` decorator and retries on specified exceptions.
            Supports optional exponential backoff between attempts.

            Args:
                fn (Callable): The function to execute.
                *args: Positional arguments to pass to the function.
                retries (int): Maximum number of attempts before failing.
                backoff_base (int, optional): Base for exponential backoff. If None, no delay is applied.
                handled_exceptions (Tuple[Type[BaseException], ...]): Exceptions to catch and retry.
                label (str): Descriptive label for logging purposes.
                **kwargs: Keyword arguments to pass to the function.

            Returns:
                Any: The result of the function call if successful.

            Raises:
                BaseException: The last caught exception if all attempts fail.
            """
            log = StaticMethods.log
            timed_fn = StaticMethods.ErrorHandling.timer(label)(fn)

            for attempt in range(1, retries + 1):
                try:
                    result = timed_fn(*args, **kwargs)
                    log.info(f"[{label}] Success on attempt {attempt}")
                    return result
                except handled_exceptions as e:
                    last_exception = e
                    log.warning(f"[{label}] Attempt {attempt}/{retries} failed: {e}")
                    if attempt < retries and backoff_base:
                        delay = backoff_base ** (attempt - 1)
                        log.info(f"[{label}] Retrying in {delay}s...")
                        time.sleep(delay)

            log.error(f"[{label}] All {retries} attempts failed.")
            raise last_exception

        @staticmethod
        def check_input(arg: Any, expected: Union[Type, Tuple[Type, ...]], label: str = "Input") -> None:
            """
            Verifies that the input matches the expected type(s). Raises TypeError if not.

            Args:
                arg (Any): The argument to check.
                expected (Type or tuple of Types): The expected type(s) (e.g., str, dict, int).
                label (str): Optional label for error clarity (e.g., function or variable name).

            Raises:
                TypeError: If the argument does not match any of the expected types.
            """
            if not isinstance(arg, expected):
                exp_types = (
                    expected.__name__
                    if isinstance(expected, type)
                    else ", ".join(t.__name__ for t in expected)
                )
                raise TypeError(f"{label} must be of type {exp_types}, but got {type(arg).__name__}.")

    timer = ErrorHandling.timer
    attempt = ErrorHandling.attempt
    recall = ErrorHandling.attempt
    check_input = ErrorHandling.check_input
    ERROR_USAGE = """
        StaticMethods ErrorHandling Aliases
        -----------------------------------

        These utility functions are exposed via aliases for convenience:

        timer(label="operation") -> Callable
            Decorator to time and log the execution duration of a function.
            Example:
                @timer("process_data")
                def process_data(): ...

        attempt(fn, *args, retries=3, backoff_base=None, handled_exceptions=(Exception,), label="operation", **kwargs) -> Any
            Execute a function with retry logic, automatic timing, and logging.
            Retries on specified exceptions and supports exponential backoff.

        recall(fn, *args, **kwargs) -> Any
            Alias for `attempt`. Useful when semantically retrying previous logic.

        check_input(arg, expected, label="Input") -> None
            Assert that an argument matches the expected type(s). Raises TypeError if not.
            Example:
                check_input(user_id, int, label="user_id")

        try_import(package_name: str) -> Module
            Attempts to import a package by name. If missing, installs via pip and retries.
            Raises RuntimeError on failure.
            Example:
                loguru = try_import("loguru")
    """

    class PathUtil:
        @staticmethod
        def normalize_path(p: str | Path) -> Path:
            """
            Normalize a string or Path-like input to a pathlib.Path object.

            Args:
                p (str | Path): Input path to normalize.

            Returns:
                Path: A pathlib-compatible Path object.
            """
            return Path(p)

        @staticmethod
        def get_mileslib_root() -> Path:
            """
            Get the root path of the installed mileslib package.

            Returns:
                Path: The absolute directory path where mileslib is located.
            """
            return Path(__file__).resolve().parent

        @staticmethod
        def ensure_path(
                path: str | Path,
                is_file: bool = False,
                create: bool = False,
                verbose: bool = False
        ) -> tuple[Path, bool]:
            """
            Ensure that a file or directory exists at the given path.

            Args:
                path (str | Path): The path to validate or create.
                is_file (bool): If True, treat path as a file (creates parent directory).
                create (bool): If True, attempt to create the path if it doesn't exist.
                verbose (bool): If True, print messages about created paths or errors.

            Returns:
                tuple[Path, bool]: A tuple with the normalized path and a bool indicating if it existed or was created.
            """
            path = Path(path)

            if path.exists():
                return path, True

            if not create:
                return path, False

            try:
                if is_file:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.touch(exist_ok=True)
                    if verbose:
                        print(f"[Created File] {path}")
                else:
                    path.mkdir(parents=True, exist_ok=True)
                    if verbose:
                        print(f"[Created Directory] {path}")
                return path, True
            except Exception as e:
                if verbose:
                    print(f"[Error Creating Path] {e}")
                return path, False

        @staticmethod
        def ensure_file_with_default(
                path: str | Path,
                default: dict | str,
                encoding: str = "utf-8"
        ) -> Path:
            """
            Ensure a file exists at the given path and has content.

            Creates and writes to the file if it doesn't exist or is empty. The default content
            can be a JSON-serializable dictionary or a plain string.

            Args:
                path (str | Path): Path to the file.
                default (dict | str): Default content to write if the file is missing or empty.
                encoding (str): File encoding to use when writing content.

            Returns:
                Path: The validated or newly created file path.

            Raises:
                TypeError: If the default content is neither a dict nor a str.
                OSError: If writing the file fails.
            """
            path = Path(path)

            should_write = not path.exists() or path.stat().st_size == 0

            if should_write:
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    content = (
                        json.dumps(default, indent=4)
                        if isinstance(default, dict)
                        else default
                        if isinstance(default, str)
                        else None
                    )
                    if content is None:
                        raise TypeError("Default must be a dict (for JSON) or a str.")

                    path.write_text(content, encoding=encoding)
                except Exception as e:
                    raise OSError(f"Failed to write default content to '{path}': {e}")

            return path

        @staticmethod
        def validate_directory(path: str | Path) -> Path:
            """
            Ensure that the given path exists and is a directory.

            Args:
                path (str | Path): Path to validate or create.

            Returns:
                Path: The validated directory path.

            Raises:
                OSError: If the directory cannot be created.
                NotADirectoryError: If the path exists but is not a directory.
            """
            path = Path(path)
            if not path.exists():
                try:
                    path.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    raise OSError(f"Failed to create directory '{path}': {e}")
            elif not path.is_dir():
                raise NotADirectoryError(f"'{path}' exists but is not a directory.")
            return path

        @staticmethod
        def validate_file(path: str | Path) -> Path:
            """
            Ensure that the given path exists and is a file.

            Args:
                path (str | Path): Path to validate.

            Returns:
                Path: The validated file path.

            Raises:
                FileNotFoundError: If the file does not exist.
                IsADirectoryError: If the path is a directory instead of a file.
            """
            path = Path(path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: '{path}'")
            if path.is_dir():
                raise IsADirectoryError(f"Expected a file but found a directory at: '{path}'")
            return path
    root = PathUtil.get_mileslib_root
    normalize_path = PathUtil.normalize_path
    ensure_path = PathUtil.ensure_path
    ensure_file_with_default = PathUtil.ensure_file_with_default
    validate_directory = PathUtil.validate_directory
    validate_file = PathUtil.validate_file
    PATH_USAGE = """
    StaticMethods PathUtil Aliases
    ------------------------------

    These utility functions wrap common file and path operations:

    root() -> Path
        Returns the root path of the installed mileslib package.
        Useful for locating bundled templates or defaults.

    normalize_path(p: str | Path) -> Path
        Normalize a string or Path-like object to a pathlib.Path.

    ensure_path(path, is_file=False, create=False, verbose=False) -> tuple[Path, bool]
        Ensure a file or directory exists. Optionally creates it.
        Returns the normalized path and a bool indicating existence or creation.

    ensure_file_with_default(path, default: dict | str, encoding="utf-8") -> Path
        Ensure a file exists and is populated. Writes JSON or text if missing or empty.

    validate_directory(path: str | Path) -> Path
        Ensure the path exists and is a directory. Raises errors if invalid.

    validate_file(path: str | Path) -> Path
        Ensure the path exists and is a file. Raises errors if invalid or missing.
    """

    class Config:
        REQUIRED_KEYS = [
            "valid", "setup_complete", "local_version", "repo_url", "token",
            "dependencies", "paths", "profile", "env_overrides", "env",
            "required", "denylist", "defaults", "meta"
        ]
        DENYLIST = ["changeme", ""]

        @staticmethod
        def _resolve_pdir(pdir: str | Path = None) -> Path:
            """
            Resolve and return a base project directory.

            Args:
                pdir (str | Path, optional): A custom directory. If None, defaults to StaticMethods.root().

            Returns:
                Path: The resolved project directory as a pathlib.Path object.
            """
            return Path(pdir or StaticMethods.root())

        @staticmethod
        def _get_config_dir(pdir: Path) -> Path:
            """
            Return the config subdirectory under a given project root.

            Args:
                pdir (Path): The base project directory.

            Returns:
                Path: Path to the 'config' directory inside the project.
            """
            return pdir / "config"

        @staticmethod
        def _find_settings_files(cfg_dir: Path, is_global: bool = False) -> list[str]:
            """
            Find valid configuration files in the config directory, based on known filename priorities.

            Args:
                cfg_dir (Path): Directory to search for configuration files.
                is_global (bool): If True, filters out secrets and .env files.

            Returns:
                list[str]: List of matching settings file paths (as strings).
            """
            # File detection based on priority
            candidates = [
                "settings.toml", "settings.yaml", "settings.yml",
                "config.json", ".secrets.toml", ".secrets.yaml", ".env"
            ]
            if is_global:
                # Restrict secret files and .env from being loaded globally
                candidates = [f for f in candidates if not f.startswith(".")]

            return [str(cfg_dir / f) for f in candidates if (cfg_dir / f).exists()]

        @staticmethod
        def _bootstrap_default_file(cfg_dir: Path) -> Path:
            """
            Create a default `settings.toml` file if it doesn't exist.

            Args:
                cfg_dir (Path): The directory where the file should be created.

            Returns:
                Path: Path to the created or existing `settings.toml` file.
            """
            path = cfg_dir / "settings.toml"
            if not path.exists():
                StaticMethods.log.info(f"[Config] No config found — creating default at {path}")
                path.write_text("[default]\nvalid = true\n", encoding="utf-8")
            return path

        @staticmethod
        def build(pdir: str | Path = None, is_global: bool = False) -> Dynaconf:
            """
            Load Dynaconf configuration based on detected settings files.

            Args:
                pdir (str | Path, optional): Project directory to search for config. Defaults to project root.
                is_global (bool): If True, limits secrets and disables .env loading.

            Returns:
                Dynaconf: A loaded Dynaconf settings object with merged environments.
            """
            cfg = StaticMethods.Config
            pdir = cfg._resolve_pdir(pdir)
            cfg_dir = cfg._get_config_dir(pdir)
            StaticMethods.validate_directory(cfg_dir)

            settings_files = cfg._find_settings_files(cfg_dir, is_global=is_global)
            if not settings_files and not is_global:
                settings_files = [str(cfg._bootstrap_default_file(cfg_dir))]

            return Dynaconf(
                settings_files=settings_files,
                envvar_prefix="MILESLIB",
                load_dotenv=not is_global,
                environments=True,
                merge_enabled=True
            )

        @staticmethod
        def get(*keys, pdir: str | Path = None, default=None, expected=None, is_global: bool = False):
            """
            Retrieve a nested configuration value using one or more keys.

            Args:
                *keys: One or more keys to traverse into the configuration.
                pdir (str | Path, optional): Optional project directory.
                default (Any): Value to return if the key path doesn't exist.
                expected (Any): If set, validates that the retrieved value matches.
                is_global (bool): Whether to use global configuration.

            Returns:
                Any: The retrieved configuration value.

            Raises:
                ValueError: If the value does not match the expected one.
                RuntimeError: If an error occurs while accessing configuration.
            """
            cfg = StaticMethods.Config
            log = StaticMethods.log
            settings = cfg.build(pdir, is_global=is_global)

            try:
                result = settings
                for key in keys:
                    result = result.get(key, default)

                if expected is not None and result != expected:
                    joined = " → ".join(map(str, keys))
                    raise ValueError(f"[Config.get] Expected {expected!r} at {joined}, got {result!r}")

                return result
            except Exception as e:
                raise RuntimeError(f"[Config.get] {e}")

        @staticmethod
        def require(
                keys: list[str],
                *,
                root: str = "env",
                denylist: list[str] = None,
                pdir: str | Path = None,
                is_global: bool = False
        ) -> bool:
            """
            Assert that a list of required keys exist and are not in the denylist.

            Args:
                keys (list[str]): Keys to verify within the configuration.
                root (str): Root section to check (e.g., "env").
                denylist (list[str], optional): Values that are considered invalid (e.g., "changeme").
                pdir (str | Path, optional): Project directory to load config from.
                is_global (bool): Whether to use global configuration.

            Returns:
                bool: True if all keys are present and valid.

            Raises:
                RuntimeError: If required keys are missing or contain denylisted values.
            """
            cfg = StaticMethods.Config
            log = StaticMethods.log
            settings = cfg.build(pdir, is_global=is_global)
            denylist = denylist or cfg.DENYLIST
            missing = []
            bad = []

            for key in keys:
                # fetch the value (None if not present)
                val = settings.get(root, {}).get(key) if root else settings.get(key)
                if val is None:
                    missing.append(key)
                elif val in denylist:
                    bad.append((key, val))

            if missing or bad:
                if missing:
                    log.warning(f"[Config.require] Missing keys: {missing}")
                if bad:
                    log.warning(f"[Config.require] Invalid values: {bad}")
                raise RuntimeError(f"Missing: {missing}\nInvalid: {bad}")

            return True

        @staticmethod
        def ensure_setup(pdir: str | Path = None):
            """
            Ensure that the configuration is valid and the environment is correctly initialized.

            Checks for required keys, validates paths, and ensures tokens are secure.
            Creates directories and files listed in the 'paths' section as needed.

            Args:
                pdir (str | Path, optional): The project directory to load configuration from.

            Raises:
                RuntimeError: If setup is incomplete, paths are invalid, or required values are insecure.
            """
            cfg = StaticMethods.Config
            log = StaticMethods.log
            settings = cfg.build(pdir, is_global=False)

            cfg.require(cfg.REQUIRED_KEYS, root=None, denylist=cfg.DENYLIST, pdir=pdir)

            paths = settings.get("paths", {})
            for label, raw_path in paths.items():
                path_obj = Path(raw_path)
                if "log" in label or "dir" in label:
                    StaticMethods.validate_directory(path_obj)
                elif ".env" in label or path_obj.suffix:
                    StaticMethods.ensure_file_with_default(path_obj, default="")

            if not settings.get("setup_complete"):
                raise RuntimeError("setup_complete is false. Please finish project setup.")

            token = settings.get("token")
            if not token or token in cfg.DENYLIST:
                raise RuntimeError("Missing or insecure token value.")

        @staticmethod
        def dump(pdir: str | Path = None, env: str = None, is_global: bool = False):
            """
            Print the full configuration as a formatted JSON string.

            Args:
                pdir (str | Path, optional): The project directory to load configuration from.
                env (str, optional): Specific environment to dump (e.g., "default", "development").
                is_global (bool): Whether to use global configuration.
            """
            cfg = StaticMethods.Config
            settings = cfg.build(pdir, is_global=is_global)
            raw = settings.as_dict(env=env)
            print(json.dumps(raw, indent=2))

        @staticmethod
        def exists(*keys, pdir: str | Path = None, is_global: bool = False) -> bool:
            """
            Check whether a given nested key exists in the configuration by
            traversing the raw dict from to_dict(), explicitly loading the
            "default" environment so JSON/TOML values under "default" are seen.
            """
            try:
                # Force to_dict to unwrap and return only the "default" section
                data = StaticMethods.Config.to_dict(
                    pdir=pdir,
                    env="default",
                    is_global=is_global
                )
                cur = data
                for key in keys:
                    if isinstance(cur, dict) and key in cur:
                        cur = cur[key]
                    else:
                        return False
                return True
            except Exception:
                return False

        @staticmethod
        def to_dict(pdir: str | Path = None, env: str = None, is_global: bool = False) -> dict:
            """
            Return the full configuration as a dictionary.

            Args:
                pdir (str | Path, optional): Project directory to load configuration from.
                env (str, optional): Specific environment to return.
                is_global (bool): Whether to use global configuration.

            Returns:
                dict: The full loaded configuration as a native dictionary.
            """
            cfg = StaticMethods.Config
            return cfg.build(pdir, is_global=is_global).as_dict(env=env)

    cfg_get = Config.get
    cfg_validate = Config.ensure_setup
    cfg_require = Config.require
    cfg_dump = Config.dump
    CONFIG_USAGE = """
    StaticMethods Config Aliases
    ----------------------------

    Configuration access and validation utilities powered by Dynaconf:

    cfg_get(*keys, pdir=None, default=None, expected=None, is_global=False) -> Any
        Retrieve a nested configuration value using one or more keys.
        Supports fallback defaults and value assertions.
        Example:
            token = cfg_get("env", "token")

    cfg_require(keys: list[str], root="env", denylist=None, pdir=None, is_global=False) -> bool
        Assert that required keys exist and do not match denylisted values.
        Raises RuntimeError if checks fail.
        Example:
            cfg_require(["token", "repo_url"])

    cfg_validate(pdir=None) -> None
        Validates core setup and required config structure for MilesLib.
        Ensures key paths and credentials exist and are secure.

    cfg_dump(pdir=None, env=None, is_global=False) -> None
        Print the full configuration as pretty-printed JSON.
        Useful for debugging and inspection.
    """

    class Logger:
        _configured = False
        _current_log_path = None
        _logger = None

        @staticmethod
        def try_import_loguru():
            """
            Import and return the loguru logger instance.

            Returns:
                loguru.logger: The loguru logger object.

            Raises:
                RuntimeError: If loguru cannot be imported or installed.
            """
            loguru = sm.try_import("loguru")
            return loguru.logger

        @staticmethod
        def get_loguru():
            """
            Return the active loguru logger after initialization.

            Returns:
                loguru.logger: The configured logger object.

            Raises:
                RuntimeError: If the logger has not been initialized via `init_logger`.
            """
            if not StaticMethods.Logger._configured:
                raise RuntimeError("Logger has not been initialized. Call init_logger() first.")
            return StaticMethods.Logger._logger

        @staticmethod
        def init_logger(
                log_dir: Path = Path("logs"),
                label: str = None,
                serialize: bool = True,
                pretty_console: bool = True,
                level: str = "INFO",
        ):
            """
            Initialize and configure the loguru logger.

            Sets up both console and file logging, with optional serialization and formatting.
            Creates a timestamped log file in the specified directory.

            Args:
                log_dir (Path): Directory to store log files. Defaults to 'logs/'.
                label (str, optional): Optional label appended to the log filename.
                serialize (bool): If True, logs are JSON-formatted.
                pretty_console (bool): If True, enables human-readable console output.
                level (str): Minimum log level to record (e.g., 'DEBUG', 'INFO').

            Returns:
                loguru.logger: The configured logger instance.
            """
            loguru = StaticMethods.Logger.try_import_loguru()

            if StaticMethods.Logger._configured:
                return loguru

            # Ensure log directory exists (uses PathUtil)
            log_dir, _ = StaticMethods.ensure_path(log_dir, is_file=False, create=True)

            timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
            label = f"_{label}" if label else ""
            log_path = log_dir / f"{timestamp}{label}.log"

            if pretty_console:
                loguru.add(sys.stderr, level=level, enqueue=True)

            loguru.add(log_path, level=level, serialize=serialize, rotation="10 MB", enqueue=True)

            StaticMethods.Logger._logger = loguru
            StaticMethods.Logger._current_log_path = log_path
            StaticMethods.Logger._configured = True
            return loguru

        @staticmethod
        def get_logger():
            """
            Return the configured logger instance, initializing it if needed.

            Returns:
                loguru.logger: The active logger object.
            """
            if not StaticMethods.Logger._configured:
                return StaticMethods.Logger.init_logger()
            return StaticMethods.Logger._logger

        @staticmethod
        def reset_logger():
            """
            Reset the logger state by removing all handlers and clearing configuration.

            Resets the internal flags and allows reinitialization via `init_logger()`.
            """
            loguru = StaticMethods.Logger.try_import_loguru()
            loguru.remove()
            StaticMethods.Logger._current_log_path = None
            StaticMethods.Logger._configured = False
            StaticMethods.Logger._logger = None

    #log = Logger.get_logger()
    #log_path = Logger._current_log_path
    #log_exists = Logger._configured
    LOGGER_USAGE = """
    Logger Aliases
    --------------

    log -> Logger.get_logger()
        Retrieve the active loguru logger instance (auto-initializes if needed).

    log_path -> Logger._current_log_path
        The full Path to the current log file (or None if uninitialized).

    log_exists -> Logger._configured
        Boolean flag indicating whether the logger has been initialized.
    """

    class Requests:
        @staticmethod
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
            log = StaticMethods.log
            sm.try_import("requests")
            sm.check_input(url, str, "url")
            sm.check_input(retries, int, "retries")
            log.info("Starting GET request", url=url)

            # define the single‐try function
            def _do_get():
                resp = requests.get(url)
                resp.raise_for_status()
                return resp

            # delegate retry logic
            return sm.attempt(_do_get, retries=retries)

        @staticmethod
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
            log = StaticMethods.log
            sm.try_import("requests")
            sm.check_input(url, str, "url")
            sm.check_input(data, dict, "data")
            sm.check_input(retries, int, "retries")
            log.info("Starting POST request", url=url, payload=data)

            def _do_post():
                resp = requests.post(url, json=data)
                resp.raise_for_status()
                return resp

            return sm.attempt(_do_post, retries=retries)

    http_get = Requests.http_get
    http_post = Requests.http_post
    REQUESTS_USAGE = """
    StaticMethods Requests Aliases
    ------------------------------

    http_get(url: str, retries=3) -> requests.Response
        Perform a GET request with automatic retry and logging.

    http_post(url: str, data: dict, retries=3) -> requests.Response
        Perform a POST request with JSON payload, retry support, and logging.
    """

sm = StaticMethods
StaticMethods.log = StaticMethods.Logger.get_logger()

# --------------------
# Dependency Tests
# --------------------

import types
from unittest import mock

class DummyModule(types.ModuleType):
    pass

def test_dependency_already_present():
    with mock.patch("importlib.util.find_spec", return_value=True):
        assert StaticMethods.Dependencies._dependency("json") is True


def test_dependency_needs_install_success():
    with mock.patch("importlib.util.find_spec", return_value=None), \
         mock.patch("subprocess.check_call") as mock_call:
        assert StaticMethods.Dependencies._dependency("fakepkg") is True
        mock_call.assert_called_once()


def test_dependency_install_failure():
    with mock.patch("importlib.util.find_spec", return_value=None), \
         mock.patch("subprocess.check_call", side_effect=Exception("fail")):
        assert StaticMethods.Dependencies._dependency("brokenpkg") is False


def test_try_import_success_no_install():
    dummy = DummyModule("dummy")
    with mock.patch("importlib.import_module", return_value=dummy):
        assert StaticMethods.Dependencies.try_import("os") is dummy

def test_try_import_success_after_install():
    dummy = DummyModule("dummy")
    call_count = {"count": 0}

    def import_side_effect(name):
        # fail only on the very first import of “something”
        if name == "something" and call_count["count"] == 0:
            call_count["count"] += 1
            raise ImportError("initial fail")
        return dummy

    with mock.patch("subprocess.check_call"), \
        mock.patch("importlib.util.find_spec", return_value=None), \
        mock.patch.object(StaticMethods.ErrorHandling, "attempt", return_value=dummy), \
        mock.patch("importlib.import_module", side_effect=import_side_effect):
            result = StaticMethods.Dependencies.try_import("something")
            assert result is dummy


def test_try_import_fails_after_install():
    # patch install and find_spec, and patch recall to also fail
    with mock.patch("subprocess.check_call"), \
        mock.patch("importlib.util.find_spec", return_value=None), \
        mock.patch.object(StaticMethods.ErrorHandling, "attempt", side_effect=ImportError("still broken")):

        # now simulate importlib always failing
        with mock.patch("importlib.import_module", side_effect=ImportError("initial fail")):
            with pytest.raises(RuntimeError, match="could not be properly loaded"):
                StaticMethods.Dependencies.try_import("badmod")

## PathUtil Tests

import json
import pytest
from pathlib import Path

PathUtil = sm.PathUtil

def test_normalize_path_str(tmp_path):
    s = str(tmp_path / "foo" / "bar.txt")
    p = PathUtil.normalize_path(s)
    assert isinstance(p, Path)
    assert p == tmp_path / "foo" / "bar.txt"


def test_normalize_path_path(tmp_path):
    p0 = tmp_path / "baz"
    p = PathUtil.normalize_path(p0)
    # should return a Path, ideally the very same object or equivalent
    assert isinstance(p, Path)
    assert p == p0


def test_get_mileslib_root_exists_and_is_dir():
    root = PathUtil.get_mileslib_root()
    assert isinstance(root, Path)
    assert root.exists()
    assert root.is_dir()


def test_ensure_path_exists(tmp_path):
    d = tmp_path / "existing_dir"
    d.mkdir()
    path, existed = PathUtil.ensure_path(d, create=False)
    assert path == d
    assert existed is True


def test_ensure_path_no_create(tmp_path):
    p = tmp_path / "missing"
    path, existed = PathUtil.ensure_path(p, create=False)
    assert path == p
    assert existed is False


def test_ensure_path_create_directory(tmp_path, capsys):
    p = tmp_path / "newdir"
    path, existed = PathUtil.ensure_path(p, create=True, verbose=True)
    captured = capsys.readouterr()
    assert path == p
    assert existed is True
    assert "[Created Directory]" in captured.out
    assert p.exists() and p.is_dir()


def test_ensure_path_create_file(tmp_path, capsys):
    p = tmp_path / "sub" / "file.txt"
    path, existed = PathUtil.ensure_path(p, is_file=True, create=True, verbose=True)
    captured = capsys.readouterr()
    assert path == p
    assert existed is True
    assert "[Created File]" in captured.out
    assert p.exists() and p.is_file()


def test_ensure_path_on_error(tmp_path, capsys, monkeypatch):
    # simulate mkdir failing
    p = tmp_path / "wontcreate"
    def fake_mkdir(*args, **kwargs):
        raise OSError("nope")
    monkeypatch.setattr(Path, "mkdir", fake_mkdir)
    path, existed = PathUtil.ensure_path(p, create=True, verbose=True)
    captured = capsys.readouterr()
    assert path == p
    assert existed is False
    assert "[Error Creating Path]" in captured.out


def test_ensure_file_with_default_json(tmp_path):
    p = tmp_path / "cfg.json"
    default = {"x": 42}
    ret = PathUtil.ensure_file_with_default(p, default)
    assert ret == p
    assert p.exists()
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data == default


def test_ensure_file_with_default_text(tmp_path):
    p = tmp_path / "readme.md"
    content = "# Hello"
    ret = PathUtil.ensure_file_with_default(p, content)
    assert ret == p
    assert p.read_text(encoding="utf-8") == content


def test_ensure_file_with_default_invalid(tmp_path):
    p = tmp_path / "bad.bin"
    with pytest.raises(OSError) as excinfo:
        PathUtil.ensure_file_with_default(p, 12345)
        assert "Default must be a dict (for JSON) or a str." in str(excinfo.value)


def test_validate_directory_creates(tmp_path):
    p = tmp_path / "dirA"
    ret = PathUtil.validate_directory(p)
    assert ret == p
    assert p.exists() and p.is_dir()


def test_validate_directory_not_dir(tmp_path):
    f = tmp_path / "afile.txt"
    f.write_text("data")
    with pytest.raises(NotADirectoryError):
        PathUtil.validate_directory(f)


def test_validate_directory_mkdir_failure(tmp_path, monkeypatch):
    p = tmp_path / "dirB"
    def fake_mkdir(*args, **kwargs):
        raise OSError("fail")
    monkeypatch.setattr(Path, "mkdir", fake_mkdir)
    with pytest.raises(OSError):
        PathUtil.validate_directory(p)


def test_validate_file_exists(tmp_path):
    f = tmp_path / "data.txt"
    f.write_text("x")
    ret = PathUtil.validate_file(f)
    assert ret == f


def test_validate_file_not_found(tmp_path):
    f = tmp_path / "nope.txt"
    with pytest.raises(FileNotFoundError):
        PathUtil.validate_file(f)


def test_validate_file_is_dir(tmp_path):
    d = tmp_path / "somedir"
    d.mkdir()
    with pytest.raises(IsADirectoryError):
        PathUtil.validate_file(d)

def test_resolve_pdir_with_path_and_str(tmp_path):
    # Path in, Path out
    p = StaticMethods.Config._resolve_pdir(tmp_path)
    assert isinstance(p, Path) and p == tmp_path

    # String in, Path out
    p2 = StaticMethods.Config._resolve_pdir(str(tmp_path))
    assert isinstance(p2, Path) and p2 == tmp_path


def test_get_config_dir(tmp_path):
    cfg_dir = StaticMethods.Config._get_config_dir(tmp_path)
    assert cfg_dir == tmp_path / "config"


def test_find_settings_files(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    # create a mix of files
    (cfg / "settings.toml").write_text("")
    (cfg / "settings.yaml").write_text("")
    (cfg / "config.json").write_text("")
    (cfg / ".secrets.toml").write_text("")
    (cfg / ".env").write_text("")

    all_files = StaticMethods.Config._find_settings_files(cfg, is_global=False)
    # should include all five, in the candidate order
    expected_all = [
        str(cfg / "settings.toml"),
        str(cfg / "settings.yaml"),
        # settings.yml wasn't created
        str(cfg / "config.json"),
        str(cfg / ".secrets.toml"),
        str(cfg / ".env"),
    ]
    assert all_files == expected_all

    public = StaticMethods.Config._find_settings_files(cfg, is_global=True)
    # filters out dot-started files
    assert public == [
        str(cfg / "settings.toml"),
        str(cfg / "settings.yaml"),
        str(cfg / "config.json"),
    ]


def test_bootstrap_default_file(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    default_path = StaticMethods.Config._bootstrap_default_file(cfg)
    assert default_path == cfg / "settings.toml"
    text = default_path.read_text(encoding="utf-8")
    assert "[default]" in text and "valid = true" in text

    # calling again should not overwrite or error
    before = default_path.stat().st_mtime
    dp2 = StaticMethods.Config._bootstrap_default_file(cfg)
    assert dp2 == default_path
    assert default_path.stat().st_mtime == before


def test_build_creates_and_loads_default(tmp_path):
    # build on empty tmp_path should create config dir + default file
    cfg_obj = StaticMethods.Config.build(tmp_path, is_global=False)
    # dynaconf should load the [default] valid = true
    assert hasattr(cfg_obj, "valid") and cfg_obj.valid is True

    # ensure the config directory and file exist
    cfg_dir = tmp_path / "config"
    assert cfg_dir.exists() and cfg_dir.is_dir()
    assert (cfg_dir / "settings.toml").exists()


def test_build_with_user_config(tmp_path):
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()

    # NOTE the "default" top-level key
    data = {
        "default": {
            "env": {"foo": "bar"},
            "top": 123
        }
    }
    (cfg_dir / "config.json").write_text(json.dumps(data))

    cfg_obj = StaticMethods.Config.build(tmp_path, is_global=False)

    # now these both work
    assert StaticMethods.Config.get("top", pdir=tmp_path) == 123
    assert StaticMethods.Config.get("env", "foo", pdir=tmp_path) == "bar"

def test_get_happy_missing_and_expected_mismatch(tmp_path):
    # prepare a JSON config that Dynaconf will load under the 'default' env
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    data = {
        "default": {
            "env": {"a": 1},
            "b": 2
        }
    }
    (cfg_dir / "config.json").write_text(json.dumps(data))

    # existing nested key
    assert StaticMethods.Config.get("env", "a", pdir=tmp_path) == 1
    # top-level key inside 'default'
    assert StaticMethods.Config.get("b", pdir=tmp_path) == 2
    # missing with default
    assert StaticMethods.Config.get("nope", pdir=tmp_path, default=999) == 999

    # expected mismatch triggers RuntimeError
    with pytest.raises(RuntimeError) as exc:
        StaticMethods.Config.get("env", "a", pdir=tmp_path, expected=2)
    assert "[Config.get]" in str(exc.value)

def test_require_success_missing_and_invalid(tmp_path, monkeypatch):
    # limit REQUIRED_KEYS for the test
    monkeypatch.setattr(StaticMethods.Config, "REQUIRED_KEYS", ["foo", "bar"], raising=False)

    # write JSON under the "default" env so Dynaconf picks it up
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    data = {
        "default": {
            "foo": 1,
            "bar": "bad"
        }
    }
    (cfg_dir / "config.json").write_text(json.dumps(data))

    # 1) OK when denylist does not include "bad"
    monkeypatch.setattr(StaticMethods.Config, "DENYLIST", ["changeme", ""], raising=False)
    assert StaticMethods.Config.require(["foo", "bar"], root=None, pdir=tmp_path) is True

    # 2) missing key triggers RuntimeError
    with pytest.raises(RuntimeError) as exc_m:
        StaticMethods.Config.require(["foo", "baz"], root=None, pdir=tmp_path)
    assert "Missing" in str(exc_m.value)

    # 3) bad value in denylist triggers RuntimeError
    monkeypatch.setattr(StaticMethods.Config, "DENYLIST", ["bad"], raising=False)
    with pytest.raises(RuntimeError) as exc_b:
        StaticMethods.Config.require(["bar"], root=None, pdir=tmp_path)
    assert "Invalid" in str(exc_b.value)

def test_exists_and_to_dict_and_dump(tmp_path, capsys):
    # write JSON under the "default" environment
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    data = {"default": {"x": 111}}
    (cfg_dir / "config.json").write_text(json.dumps(data))

    # now exists() will see "x"
    assert StaticMethods.Config.exists("x", pdir=tmp_path) is True
    assert StaticMethods.Config.exists("nope", pdir=tmp_path) is False

    # to_dict() should expose the same value
    d = StaticMethods.Config.to_dict(pdir=tmp_path)
    assert isinstance(d, dict) and d.get("x") == 111

    # dump() prints it out as JSON
    StaticMethods.Config.dump(pdir=tmp_path)
    out = capsys.readouterr().out.strip()
    parsed = json.loads(out)
    assert parsed.get("x") == 111
