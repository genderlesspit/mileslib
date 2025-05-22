import shutil
from unittest import mock
import pytest
import importlib.util
import requests
import toml
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
import click

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

        # Deprecated
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

    class FileIO:
        SUPPORTED_FORMATS = ["txt", "toml", "json", "env", "yml", "yaml"]

        @staticmethod
        def read(path: Path, ext: str, section: str = None) -> dict:
            if not path.exists():
                print(f"[FileIO] File not found: {path}")
                return {}

            ext = ext.lower()
            print(f"[FileIO] Reading {ext} config from {path}")

            if ext == "toml":
                import toml
                content = toml.load(path)
            elif ext == "json":
                content = json.loads(path.read_text(encoding="utf-8"))
            elif ext == "env":
                content = {}
                for line in path.read_text().splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, v = line.split("=", 1)
                        content[k.strip()] = v.strip().strip('"')
            elif ext in ("yaml", "yml"):
                try:
                    import yaml
                except ImportError:
                    raise ImportError("Install PyYAML to use YAML/YML support.")
                content = yaml.safe_load(path.read_text())
            elif ext == "txt":
                content = {"content": path.read_text(encoding="utf-8")}
            else:
                raise ValueError(f"[FileIO] Unsupported config format: {ext}")

            if section and isinstance(content, dict):
                return content.get(section, {})
            return content

        @staticmethod
        def write(path: Path, ext: str, data: dict, overwrite: bool = False, replace_existing: bool = False,
                  section: str = "default"):
            ext = ext.lower()
            print(f"[FileIO] Writing {ext} config to {path}")
            merged_data = data

            if not overwrite and path.exists():
                print("[FileIO] File exists — merging data")
                existing = StaticMethods.FileIO.read(path, ext)

                if ext in ("toml", "json", "yaml", "yml"):
                    base = existing.get(section, {}) if section else existing
                    merged = StaticMethods.FileIO._merge(base, data, replace_existing)
                    merged_data = {section: merged} if section else merged
                else:
                    merged = StaticMethods.FileIO._merge(existing, data, replace_existing)
                    merged_data = merged
            else:
                print("[FileIO] Overwriting existing config")
                if ext in ("toml", "json", "yaml", "yml") and section:
                    merged_data = {section: data}

            if ext == "toml":
                import toml
                path.write_text(toml.dumps(merged_data), encoding="utf-8")
            elif ext == "json":
                path.write_text(json.dumps(merged_data, indent=2), encoding="utf-8")
            elif ext == "env":
                with path.open("w", encoding="utf-8") as f:
                    for k, v in merged_data.items():
                        f.write(f'{k}="{v}"\n')
            elif ext in ("yaml", "yml"):
                try:
                    import yaml
                except ImportError:
                    raise ImportError("Install PyYAML to use YAML/YML support.")
                with path.open("w", encoding="utf-8") as f:
                    yaml.safe_dump(merged_data, f)
            elif ext == "txt":
                if not isinstance(data, dict) or "content" not in data:
                    raise ValueError("TXT write requires {'content': str}")
                path.write_text(data["content"], encoding="utf-8")
            else:
                raise ValueError(f"[StaticMethods.FileIO] Unsupported config format: {ext}")

        @staticmethod
        def _merge(base: dict, new: dict, replace: bool = False) -> dict:
            print(f"[FileIO] Merging config: replace_existing={replace}")
            merged = base.copy()
            for k, v in new.items():
                if k not in merged or replace:
                    merged[k] = v
            return merged

    class Config:
        REQUIRED_KEYS = [
            "valid", "setup_complete", "local_version", "repo_url", "token",
            "dependencies", "paths", "profile", "env_overrides", "env",
            "required", "denylist", "defaults", "meta"
        ]
        DENYLIST = ["changeme", ""]

        @staticmethod
        def _resolve_pdir(pdir):
            """
            Resolve the base project directory.

            Args:
                pdir (str | Path, optional): Custom project root path.
                                             If None, defaults to StaticMethods.root().

            Returns:
                Path: Absolute project directory as a pathlib.Path object.
            """
            return Path(pdir or StaticMethods.root())

        @staticmethod
        def _get_config_dir(pdir):
            """
            Return the configuration directory path under the given project directory.

            Args:
                pdir (Path): Root project directory.

            Returns:
                Path: Path to the project's 'config/' folder.
            """
            return Path(pdir) / "_config"

        @staticmethod
        def _default_file_name():
            """
            Return the default configuration file name.

            Returns:
                str: The fallback config file name, e.g., 'settings.toml'.
            """
            return "settings.toml"

        @staticmethod
        def _find_settings_file(cfg_dir, is_global=False):
            """
            Search for the first available config file in a known priority order.

            Args:
                cfg_dir (Path): The directory to search within.
                is_global (bool): If True, skips secrets like .env and .secrets.* files.

            Returns:
                Path: The first matching config file path found.
            """
            candidates = [
                "settings.toml", "settings.yaml", "settings.yml",
                "config.json", ".secrets.toml", ".secrets.yaml", ".env",
                "mileslib_config.toml"
            ]
            if is_global:
                candidates = [f for f in candidates if not f.startswith(".")]

            for name in candidates:
                path = cfg_dir / name
                if path.exists():
                    return path

            return None

        @staticmethod
        def build(pdir=None, is_global=False, file_name=None) -> dict:
            """
            Load configuration from the resolved config file into a native dictionary.

            Uses StaticMethods.FileIO for reading and supports fallback creation
            if no file is found.

            Args:
                pdir (str | Path, optional): Project root. Defaults to StaticMethods.root().
                is_global (bool): If True, disables loading secrets and .env files.
                file_name (str, optional): Specific config file to load (e.g., 'custom.toml').

            Returns:
                dict: Parsed configuration dictionary.
            """
            pdir = StaticMethods.Config._resolve_pdir(pdir)
            cfg_dir = StaticMethods.Config._get_config_dir(pdir)
            cfg_dir.mkdir(parents=True, exist_ok=True)

            if file_name:
                file_path = cfg_dir / file_name
            else:
                file_path = StaticMethods.Config._find_settings_file(cfg_dir, is_global)

            if file_path is None or not file_path.exists():
                file_path = cfg_dir / (file_name or StaticMethods.Config._default_file_name())
                StaticMethods.FileIO.write(file_path, "toml", {"valid": True}, overwrite=True)

            ext = file_path.suffix.lstrip(".")
            return StaticMethods.FileIO.read(file_path, ext)

        @staticmethod
        def write(pdir=None, file_name="settings.toml", data=None, overwrite=False, replace_existing=False):
            """
            Write configuration data to the specified config file using FileIO.

            Supports overwrite or merge mode, depending on flags provided.

            Args:
                pdir (str | Path, optional): Project root directory.
                file_name (str): Name of the file to write (e.g., 'settings.toml').
                data (dict): Data to write.
                overwrite (bool): If True, replace the file entirely.
                replace_existing (bool): If False, keep existing values unless missing.
            """
            pdir = StaticMethods.Config._resolve_pdir(pdir)
            cfg_dir = StaticMethods.Config._get_config_dir(pdir)
            cfg_dir.mkdir(parents=True, exist_ok=True)

            file_path = cfg_dir / file_name
            ext = file_path.suffix.lstrip(".")

            StaticMethods.FileIO.write(file_path, ext, data or {}, overwrite, replace_existing)

        @staticmethod
        def get(*keys, pdir=None, default=None, expected=None, is_global=False, section="default"):
            data = StaticMethods.Config.build(pdir=pdir, is_global=is_global)

            if section and isinstance(data, dict):
                data = data.get(section, {})

            try:
                for key in keys:
                    if isinstance(data, dict):
                        data = data.get(key, default)
                    else:
                        return default

                if expected is not None and data != expected:
                    raise ValueError(f"[Config.get] Expected {expected!r}, got {data!r}")
                return data
            except Exception as e:
                raise RuntimeError(f"[Config.get] {e}")

        @staticmethod
        def require(keys, root="env", denylist=None, pdir=None):
            """
            Ensure that required configuration keys exist and are not denylisted.

            Args:
                keys (list[str]): Keys to check under the root (e.g., ['token', 'repo_url']).
                root (str): Top-level config section to look in (default: 'env').
                denylist (list[str], optional): Values considered invalid.
                pdir (str | Path, optional): Project root directory.

            Returns:
                bool: True if all keys are valid.

            Raises:
                RuntimeError: If required keys are missing or contain denylisted values.
            """
            cfg = StaticMethods.Config.build(pdir)
            denylist = denylist or StaticMethods.Config.DENYLIST
            missing = []
            invalid = []

            for key in keys:
                val = cfg.get(root, {}).get(key) if root else cfg.get(key)
                if val is None:
                    missing.append(key)
                elif val in denylist:
                    invalid.append(key)

            if missing or invalid:
                raise RuntimeError(f"Missing: {missing}, Invalid: {invalid}")
            return True

        @staticmethod
        def dump(pdir=None, file_name=None):
            """
            Print the current configuration contents as formatted JSON.

            Useful for debugging or CLI inspection.

            Args:
                pdir (str | Path, optional): Project directory.
                file_name (str, optional): Config file to dump (default: auto-detect).
            """
            cfg = StaticMethods.Config.build(pdir, file_name=file_name)
            print(json.dumps(cfg, indent=2))

    cfg_get = Config.get
    cfg_require = Config.require
    cfg_dump = Config.dump
    cfg_write = Config.write
    cfg_build = Config.build
    CONFIG_USAGE = """
    StaticMethods Config Aliases
    ----------------------------

    Lightweight configuration utilities powered by FileIO.

    cfg_get(*keys, pdir=None, default=None, expected=None, section="default") -> Any
        Retrieve a nested configuration value using one or more keys.
        Supports default fallback and optional value assertion.
        Example:
            token = cfg_get("env", "token")

    cfg_require(keys: list[str], root="env", denylist=None, pdir=None) -> bool
        Ensure specified keys exist and do not contain denylisted values.
        Raises RuntimeError if validation fails.
        Example:
            cfg_require(["repo_url", "token"])

    cfg_dump(pdir=None, file_name=None) -> None
        Print the active configuration as pretty-printed JSON.
        Useful for debugging and inspection.
        Example:
            cfg_dump()

    cfg_write(pdir=None, file_name="settings.toml", data=None, overwrite=False, replace_existing=False)
        Write configuration data to file. Supports TOML, JSON, ENV, YAML.
        If overwrite is False, existing values will be preserved unless replace_existing=True.
        Example:
            cfg_write(data={"token": "abc123"})

    cfg_build(pdir=None, is_global=False, file_name=None) -> dict
        Load configuration from disk into a raw dictionary.
        Automatically bootstraps missing files with a default schema.
        Example:
            config = cfg_build()
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
            loguru = StaticMethods.try_import("loguru")
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

    # log = Logger.get_logger()
    # log_path = Logger._current_log_path
    # log_exists = Logger._configured
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
            StaticMethods.try_import("requests")
            StaticMethods.check_input(url, str, "url")
            StaticMethods.check_input(retries, int, "retries")
            log.info("Starting GET request", url=url)

            # define the single‐try function
            def _do_get():
                resp = requests.get(url)
                resp.raise_for_status()
                return resp

            # delegate retry logic
            return StaticMethods.attempt(_do_get, retries=retries)

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
            StaticMethods.try_import("requests")
            StaticMethods.check_input(url, str, "url")
            StaticMethods.check_input(data, dict, "data")
            StaticMethods.check_input(retries, int, "retries")
            log.info("Starting POST request", url=url, payload=data)

            def _do_post():
                resp = requests.post(url, json=data)
                resp.raise_for_status()
                return resp

            return StaticMethods.attempt(_do_post, retries=retries)

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

StaticMethods.log = StaticMethods.Logger.get_logger()  # this is for testing purposes only
sm = StaticMethods
log = StaticMethods.Logger.get_logger()

class Directory:
    """
    Handles root directory validation, configuration setup, and global project state.

    Attributes:
        setup_complete (bool): Indicates whether initialization has completed.
        absolute_path (Path): The validated root directory of the MilesLib project.
    """
    setup_complete = False
    absolute_path = None

    def __init__(self, root: Path = None):
        """
        Initialize the Directory object and set up the core configuration structure.

        Args:
            root (Path, optional): Custom root path. Defaults to current working directory.

        Raises:
            ValueError: If the directory or config file cannot be created or validated.
        """
        self.root = sm.validate_directory((root or os.getcwd()).resolve())
        Directory.absolute_path = self.root
        self.config_name = "mileslib_config.toml"
        self.config_dir = sm.validate_directory(self.root / "_config")
        try:
            self.config_path = sm.validate_file(self.config_dir / self.config_name )
        except FileNotFoundError:
            sm.cfg_write(
                pdir=self.root,
                file_name=self.config_name,
                data={
                    "valid": True,
                    "absolute_root": f"{self.root}",
                    "active_projects": {
                    }
                },
                overwrite=False,
                replace_existing=False
            )
        except IsADirectoryError:
            raise RuntimeError("Config file is actually a directory...? How did this happen?")

        Directory.setup_complete = True

    @staticmethod
    def validate():
        """
        Ensure the MilesLib project root is properly initialized and accessible.

        This method follows a multi-step validation flow:
          1. If `Directory.absolute_path` is already set, return it immediately.
          2. Otherwise, attempt to load the project root from the local config file at `_config/mileslib_config.toml`.
          3. If the config is missing or malformed, automatically invoke `mileslib setup` via subprocess.
          4. After setup, retry loading the configuration to finalize initialization.

        Returns:
            Path: The absolute path of the MilesLib project root.

        Raises:
            RuntimeError: If initialization fails due to missing config, setup failure, or unreadable config state.
        """
        def _load_from_config() -> Path:
            """
            Restore Directory.absolute_path from the on-disk config file.
            """
            print("[validate] Attempting to load config from disk...")
            root = Path(os.getcwd()).resolve()
            config_path = root / "_config" / "mileslib_config.toml"
            print(f"[validate] Looking for config at: {config_path}")

            if not config_path.exists():
                print("[validate] Config file does not exist.")
                raise RuntimeError("Could not initialize from config. Run `mileslib setup` first.")

            print("[debug] Using pdir for cfg_get:", root)
            absolute_root_str = sm.cfg_get("absolute_root", pdir=root)
            print("[debug] absolute_root from config:", absolute_root_str)

            if absolute_root_str is None:
                raise RuntimeError("Config file is missing 'absolute_root'. Run `mileslib setup` again.")

            absolute_path = Path(absolute_root_str)

            if not absolute_path.exists():
                print("[validate] Config absolute_root path does not exist on filesystem.")
                raise RuntimeError("Could not initialize from config. Run `mileslib setup` first.")

            Directory.absolute_path = absolute_path
            Directory.setup_complete = True
            print(f"[validate] Directory initialized from config: {absolute_path}")
            print(f"Acknowledged Directory class setup: {Directory.setup_complete}")
            print(f"Acknowledged Directory class absolute path: {Directory.absolute_path}")

            return absolute_path

        def _setup():
            print("[validate] Running setup subprocess...")
            result = subprocess.run(
                ["python", "-m", "mileslib", "setup"],
                capture_output=True,
                text=True
            )

            print("[stdout]", result.stdout)
            print("[stderr]", result.stderr)
            print("[exit code]", result.returncode)

            if result.returncode != 0:
                print("[error] MilesLib setup failed.")
                raise RuntimeError("Critical error with core MilesLib setup logic. Please report on github.")
            else:
                print("[success] MilesLib root initialized.")

        if Directory.setup_complete is True and Directory.absolute_path.exists():
            print(f"[validate] Already marked complete: {Directory.absolute_path}")
            return Directory.absolute_path

        print(f"[validate] Could not initialize. Attempting to find config...")
        try:
            return _load_from_config()
        except RuntimeError as e:
            print(f"[validate] Config load failed: {e}")
            print("[validate] Config not found or invalid. Attempting setup...")
            _setup()
            return _load_from_config()

#IS_INITIALIZED = Directory.is_initialized()
DIRECTORY_USAGE="""
MilesLib Directory Constants
----------------------------

• IS_INITIALIZED
    → bool: True if MilesLib root has been initialized via Directory().
    → Raises RuntimeError if accessed before initialization.
    → Alias: Directory.is_initialized()

• ABSOLUTE_PATH
    → Path: The absolute root directory of the current MilesLib project.
    → Set automatically during Directory() instantiation.
    → Alias: Directory.absolute_path
"""

class CLI:
    """
    Command-line interface handler for MilesLib commands.

    Methods:
        launch(): Starts the CLI command group.
    """
    def __init__(self):
        """
        Initialize the CLI with command registration.
        """
        self.cli = click.Group(
            invoke_without_command=True,
            context_settings={"help_option_names": ["--help", "-h"]}
        )
        self._register_commands()

    def launch(self):
        """
        Launch the CLI group. Entry point for CLI execution.
        """
        self.cli()

    def _register_commands(self):
        """
        Register all subcommands to the CLI group.
        """
        self.cli.add_command(self.CMDs.run_setup)
        self.cli.add_command(self.CMDs.run_init)

    class CMDs:
        #RUN SETUP
        @staticmethod
        @click.command(name="setup")
        @click.option(
            "--root",
            type=click.Path(file_okay=False, dir_okay=True),
            default=".",
            show_default=True,
            help="Root directory to initialize MilesLib in.",
        )
        def run_setup(root):
            """
            Set up the MilesLib root directory and configuration file.

            Args:
                root (str): Path to the desired root directory.

            Side Effects:
                Creates `_config/mileslib_config.toml` and sets Directory.absolute_path.

            Raises:
                click.Abort: If setup fails due to a validation or filesystem error.
            """
            try:
                root_path = Path(root).resolve()
                Directory(root_path)
                click.echo(f"[setup] MilesLib initialized at: {root_path}")
            except Exception as e:
                click.echo(f"[error] Failed to initialize MilesLib: {e}")
                raise click.Abort()

        #RUN INITIALIZATION
        @staticmethod
        @click.command(name="init")
        @click.argument("project_name")
        def run_init(project_name):
            """
            Initialize a new MilesLib-compatible project under the current root.

            Args:
                project_name (str): Name of the new project directory to create.

            Raises:
                RuntimeError: If MilesLib root is not initialized.
            """
            try:
                CLI.Methods.init_project(project_name)
            except RuntimeError as e:
                click.echo(str(e))
                raise click.Abort()

    class Methods:
        @staticmethod
        def init_project(project_name: str):
            """
            Create a new project folder with default structure and Django scaffold.

            Args:
                project_name (str): Name of the project to be created.

            Side Effects:
                - Creates folders: _config, _tests, _logs, .tmp
                - Writes a default settings.toml config file
                - Runs `django-admin startproject`

            Raises:
                RuntimeError: If root is not initialized.
                subprocess.CalledProcessError: If Django project creation fails.
            """

            #Validate Directory
            click.echo("[debug] Validating Directory ...")
            try:
                root = Directory.validate() / project_name
                click.echo(f"[debug] {root} successfully identified as project root.")
            except Exception as e:
                click.echo(f"[validate error]: {e}")
                raise click.Abort

            cfg = root / "_config"
            tests = root / "_tests"
            logs = root / "_logs"
            tmp = root / ".tmp"

            try:
                click.echo("[init] Initializing Django project...")
                subprocess.run(
                    ["python", "-m", "django", "startproject", project_name, Directory.absolute_path],
                    check=True
                )

                click.echo(f"[init] Creating directories for '{project_name}'...")
                for d in [root, cfg, tests, logs, tmp]:
                    sm.validate_directory(d)

                click.echo("[init] Writing default configuration...")
                sm.cfg_write(
                    pdir=root,
                    file_name="settings.toml",
                    data={
                        "valid": True,
                        "project": project_name,
                        "env": {"active": "default"},
                        "paths": {
                            "config": str(cfg),
                            "logs": str(logs),
                            "tmp": str(tmp)
                        }
                    },
                    overwrite=False,
                    replace_existing=False
                )

            except Exception as e:
                click.echo(f"[error] {project_name} initialization failed!: {e}")
                if root.exists():
                    shutil.rmtree(root)
                click.echo("[abort] Setup aborted.")
                exit(1)

# Entry point
if __name__ == "__main__":
    CLI().launch()