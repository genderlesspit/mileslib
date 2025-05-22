import shutil
from unittest import mock
import pytest
import importlib.util
import requests
import toml
from typing import Any, List, Union, Mapping, Sequence, Callable, Tuple, Type, Optional, Dict
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

from click import Abort
from click.exceptions import Exit
from dynaconf import Dynaconf
import click
import re
import textwrap

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
        def write(
                path: Path,
                ext: str,
                data: dict,
                overwrite: bool = False,
                replace_existing: bool = False,
                section: str = None
        ):
            ext = ext.lower()
            print(f"[FileIO] Writing {ext} config to {path}")
            merged_data = {}

            if not overwrite and path.exists():
                print("[FileIO] File exists — merging data")
                existing = StaticMethods.FileIO.read(path, ext)

                if ext in ("toml", "json", "yaml", "yml"):
                    if section:
                        base = existing.get(section, {})
                        merged = StaticMethods.FileIO._merge(base, data, replace_existing)
                        existing[section] = merged
                        merged_data = existing
                    else:
                        merged_data = StaticMethods.FileIO._merge(existing, data, replace_existing)
                else:
                    merged_data = StaticMethods.FileIO._merge(existing, data, replace_existing)
            else:
                print("[FileIO] Overwriting existing config")
                if ext in ("toml", "json", "yaml", "yml"):
                    merged_data = {section: data} if section else data
                else:
                    merged_data = data

            # Write to disk
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
                raise ValueError(f"[FileIO] Unsupported config format: {ext}")

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
        def write(pdir=None, file_name="settings.toml", data=None, section=None, overwrite=False,
                  replace_existing=False):
            """
            Write configuration data to the specified config file using FileIO.

            Supports full overwrite, partial merging, and nested section targeting via dot notation.

            Args:
                pdir (str | Path, optional): Project root directory.
                file_name (str): Name of the file to write (e.g., 'settings.toml').
                data (dict): Data to write.
                section (str, optional): Dot-path to section (e.g., 'default.active_projects').
                overwrite (bool): If True, replaces the file completely.
                replace_existing (bool): If False, preserves existing keys unless missing.
            """
            pdir = StaticMethods.Config._resolve_pdir(pdir)
            cfg_dir = StaticMethods.Config._get_config_dir(pdir)
            cfg_dir.mkdir(parents=True, exist_ok=True)

            file_path = cfg_dir / file_name
            ext = file_path.suffix.lstrip(".")

            # Read existing data unless full overwrite
            existing_data = {}
            if not overwrite and file_path.exists():
                existing_data = StaticMethods.FileIO.read(file_path, ext) or {}

            # Normalize all values (convert Path → str)
            flattened_data = {
                str(k): str(v) if isinstance(v, Path) else v
                for k, v in (data or {}).items()
            }

            if section:
                # Traverse or create nested section structure
                section_keys = section.split(".")
                ref = existing_data
                for key in section_keys:
                    ref = ref.setdefault(key, {})

                for k, v in flattened_data.items():
                    if replace_existing or k not in ref:
                        ref[k] = v
            else:
                for k, v in flattened_data.items():
                    if replace_existing or k not in existing_data:
                        existing_data[k] = v

            print("[cfg_write] FINAL write object:")
            print(json.dumps(existing_data, indent=2))
            # Always overwrite the file with updated merged structure
            StaticMethods.FileIO.write(file_path, ext, existing_data, overwrite=True)

        @staticmethod
        def get(*keys, pdir=None, default=None, expected=None, is_global=False, section=None):
            data = StaticMethods.Config.build(pdir=pdir, is_global=is_global)
            if section:
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
        config_path = self.config_dir / self.config_name

        try:
            self.config_path = sm.validate_file(config_path)
        except FileNotFoundError:
            print("[debug] Config file not found, writing new one...")
            try:
                sm.cfg_write(
                    pdir=self.root,
                    file_name=self.config_name,
                    data={
                        "valid": True,
                        "absolute_root": str(self.root),
                    },
                    section="mileslib",
                    overwrite=False,
                    replace_existing=False
                )
            except Exception as e:
                raise RuntimeError(f"[cfg_write error] {e}")

            # Now confirm it's there
            if not config_path.exists():
                raise RuntimeError(f"Config still missing after write: {config_path}")
            self.config_path = sm.validate_file(config_path)
        except IsADirectoryError:
            raise RuntimeError("Config file is actually a directory...?")

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
            absolute_root_str = sm.cfg_get("absolute_root", pdir=root, section="mileslib")
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
            cmd = ["python", "-m", "mileslib", "setup"]
            print(f"[subprocess] Calling: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            print(f"[subprocess stdout]\n{result.stdout}")
            print(f"[subprocess stderr]\n{result.stderr}")
            print(f"[subprocess exit code]: {result.returncode}")

            if result.returncode != 0:
                raise RuntimeError("Critical error with core MilesLib setup logic.")

        if Directory.setup_complete is True and Directory.absolute_path.exists():
            print(f"[validate] Already marked complete: {Directory.absolute_path}")
            return Directory.absolute_path

        print(f"[validate] No class level variables present.")
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
        print(f"[debug] CLI args: {sys.argv}")
        self.Project.dispatch_or_fallback(self.cli)  # <- new dynamic entrypoint

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

            proj_root = sm.validate_directory(root)
            proj_root_str = repr(str(proj_root))
            absolute_path_str = repr(str(Directory.absolute_path))

            cfg = root / "_config"
            tests = root / "_tests"
            logs = root / "_logs"
            tmp = root / ".tmp"
            django_name = f"{project_name}_core"

            def init_django():
                click.echo("[init] Initializing Django project...")
                subprocess.run(
                    ["python", "-m", "django", "startproject", django_name, proj_root],
                    check=True
                )

            def init_directories():
                click.echo(f"[init] Creating directories for '{project_name}'...")
                for d in [root, cfg, tests, logs, tmp]:
                    sm.validate_directory(d)

            def init_config():
                click.echo("[init] Writing default configuration...")
                db_name = f"{project_name}_db"

                sm.cfg_write(
                    pdir=root,
                    file_name="settings.toml",
                    data={
                        "valid": True,
                        "project": project_name,
                        "database_name": db_name,
                        "env": {"active": "default"},

                        "paths": {
                            "absolute_root": str(Directory.absolute_path),
                            "project_root": str(proj_root),
                            "config": str(cfg),
                            "logs": str(logs),
                            "tmp": str(tmp),
                        },

                        "database": {
                            "engine": "postgresql",
                            "host": "${DB_HOST}",
                            "port": "${DB_PORT}",
                            "name": "${DB_NAME}",
                            "user": "${DB_USER}",
                            "password": "${DB_PASS}",
                        },

                        "aad": {
                            "server": "${AAD_SERVER}",
                            "client_id": "${AAD_CLIENT_ID}",
                            "client_secret": "${AAD_CLIENT_SECRET}",  # Optional, for confidential apps
                            "tenant_id": "${AAD_TENANT_ID}",
                            "scopes": "${AAD_SCOPES}",
                            "authority": "https://login.microsoftonline.com/${AAD_TENANT_ID}",
                            "redirect_uri": "http://localhost:8000/oauth2/login/",  # can override per env
                        }
                    },
                    overwrite=False,
                    replace_existing=False
                )

            def init_env():
                db_name = f"{project_name}_db"
                env_data = {
                    "DB_HOST": "localhost",
                    "DB_PORT": "5432",
                    "DB_NAME": db_name,
                    "DB_USER": "admin",
                    "DB_PASS": "changeme",

                    "AAD_SERVER": "login.microsoftonline.com/<tenant-id>",
                    "AAD_CLIENT_ID": "<your-client-id-guid>",
                    "AAD_CLIENT_SECRET": "<your-secret>",  # if using client credentials flow
                    "AAD_TENANT_ID": "<your-tenant-guid>",
                    "AAD_SCOPES": "User.Read openid profile offline_access"
                }

                sm.FileIO.write(
                    path=cfg / ".env",
                    ext="env",
                    data=env_data,
                    overwrite=True,
                    replace_existing=True
                )
                env_file = sm.validate_file(path=Path(cfg / ".env"))
                if env_file.exists() is False:
                    raise FileNotFoundError("Could not locate .env file!")
                env_read = sm.FileIO.read(env_file, ext="env")
                if env_read is None:
                    raise AttributeError("Failed to write to .env file!")

            def init_global_variables():
                """Write a global.py file that exposes project constants for DB, AAD, and project paths."""
                global_file = proj_root / "global.py"

                content = textwrap.dedent(f"""\
                    from pathlib import Path
                    import os
                    from dotenv import load_dotenv
                    from mileslib import StaticMethods as sm

                    # Auto-generated by MilesLib init_project

                    # === Load .env ===
                    dotenv_path = Path(__file__).parent / ".env"
                    load_dotenv(dotenv_path=dotenv_path)

                    # === PostgreSQL Configuration ===
                    DB_HOST = os.getenv("DB_HOST", "localhost")
                    DB_PORT = os.getenv("DB_PORT", "5432")
                    DB_NAME = os.getenv("DB_NAME", "")
                    DB_USER = os.getenv("DB_USER", "")
                    DB_PASS = os.getenv("DB_PASS", "")

                    # === Azure Active Directory / MSAL Configuration ===
                    AAD_SERVER = os.getenv("AAD_SERVER")  # e.g., login.microsoftonline.com/<tenant-id>
                    AAD_CLIENT_ID = os.getenv("AAD_CLIENT_ID")  # Azure AD App Client ID
                    AAD_CLIENT_SECRET = os.getenv("AAD_CLIENT_SECRET")  # Optional for confidential apps
                    AAD_TENANT_ID = os.getenv("AAD_TENANT_ID")  # Used to build authority
                    AAD_SCOPES = os.getenv("AAD_SCOPES", "User.Read")  # space-separated or comma-separated scopes
                    AAD_AUTHORITY = f"https://login.microsoftonline.com/{{AAD_TENANT_ID}}" if AAD_TENANT_ID else None

                    # === Project Paths ===
                    ABSOLUTE_ROOT = Path(
                        sm.cfg_get('absolute_root', pdir={absolute_path_str}, section='paths')
                    )
                    PROJECT_ROOT = Path(
                        sm.cfg_get('project_root', pdir={proj_root_str}, section='paths')
                    )
                """)

                global_file.write_text(content, encoding="utf-8")
                print(f"[init] Wrote global constants to {global_file}")

            def acknowledge_project():
                click.echo("[init] Acknowledging project globally...")
                sm.cfg_write(
                    pdir=Directory.absolute_path,
                    file_name="mileslib_config.toml",
                    data={
                        f"{project_name}": str(proj_root)
                    },
                    section="active_projects"
                )

            def scaffold_gitignore():
                """Generate a default .gitignore file for Python/Django projects."""
                gitignore_path = proj_root / ".gitignore"
                if gitignore_path.exists():
                    print(f"[gitignore] .gitignore already exists. Skipping.")
                    return

                content = textwrap.dedent("""\
                    __pycache__/
                    *.pyc
                    *.pyo
                    *.log
                    .env
                    .DS_Store
                    db.sqlite3
                    /postgres_data/
                    /tmp/
                    .pytest_cache/
                    .venv/
                    .mypy_cache/
                    *.sqlite3
                """)
                gitignore_path.write_text(content, encoding="utf-8")
                print(f"[gitignore] Generated .gitignore")

            def scaffold_requirements():
                """Create a minimal requirements.txt if one doesn't exist."""
                req_path = proj_root / "requirements.txt"
                if req_path.exists():
                    print("[req] requirements.txt already exists. Skipping.")
                    return

                content = textwrap.dedent("""\
                    Django>=4.2
                    psycopg2-binary
                    python-dotenv
                """)
                req_path.write_text(content, encoding="utf-8")
                print(f"[req] Generated requirements.txt")

            def scaffold_readme():
                """Create a starter README.md for the project."""
                readme_path = proj_root / "README.md"
                if readme_path.exists():
                    print("[readme] README.md already exists. Skipping.")
                    return

                content = textwrap.dedent("""\
                    Django>=4.2
                    psycopg2-binary
                    python-dotenv
                    django-auth-adfs  # AAD support
                    msal  # Optional: for other MSAL-based auth
                """)
                readme_path.write_text(content, encoding="utf-8")
                print(f"[readme] Generated README.md")

            try:
                init_django()
                init_directories()
                init_config()
                init_env()
                init_global_variables()
                acknowledge_project()

                scaffold_gitignore()
                scaffold_requirements()
                scaffold_readme()

            except Exception as e:
                click.echo(f"[error] {project_name} initialization failed!: {e}")
                if root.exists():
                    shutil.rmtree(root)
                click.echo("[abort] Setup aborted.")
                exit(1)

    class Project:
        @staticmethod
        def dispatch_or_fallback(main_cli):
            args = sys.argv[1:]
            if not args or args[0].startswith("-"):
                return main_cli()  # no project name provided, run top-level CLI

            project_name = args[0]
            try:
                root = Directory.validate()
                config = sm.cfg_get("active_projects", pdir=root)
                if project_name not in config:
                    click.echo(f"[error] Unknown project: '{project_name}'")
                    return main_cli()

                project_path = Path(config[project_name])
                ctx = {"project": project_name, "project_path": project_path}

                # Dispatch to the project CLI with remaining args
                try:
                    CLI.Project.project_cli().main(args=args[1:], obj=ctx, standalone_mode=False)
                except (Exit, Abort):
                    # These are normal flow-control exits from Click (Abort is a subclass of Exit, but be explicit for clarity)
                    sys.exit(1)
                except Exception as e:
                    click.echo(f"[critical] Could not dispatch project command: {e}")
                    return main_cli()

            except Exception as e:
                click.echo(f"[critical] Could not dispatch project command: {e}")
                return main_cli()

        @staticmethod
        def project_cli():
            if not CLI.Project.Diagnostics.DIAGNOSTICS:
                CLI.Project.Diagnostics.run()

            @click.group()
            @click.pass_context
            def cli(ctx):
                """Project-scoped commands"""
                pass

            cli.add_command(CLI.Project.CMDs.run_diagnostic)
            # Add future project-specific subcommands here
            return cli

        class CMDs:
            @staticmethod
            @click.command(name="diagnostic")
            @click.option("--repair", is_flag=True, help="Attempt to auto-repair any failed checks.")
            @click.pass_context
            def run_diagnostic(ctx, repair):
                """
                Run full project diagnostics.

                Args:
                    ctx (click.Context): CLI context
                    repair (bool): Whether to auto-repair
                """
                try:
                    project = ctx.obj["project"]
                    path = ctx.obj["project_path"]
                    CLI.Project.Methods.run_diagnostic_logic(project, path, repair)
                except Exception as e:
                    click.echo(f"[error] Diagnostic failed: {e}")
                    raise click.Abort()

        class Methods:
            @staticmethod
            def run_diagnostic_logic(project: str, path: Path, auto_repair: bool = False):
                ctx = {"project": project, "project_path": path}
                errors = CLI.Project.Diagnostics.run_all(ctx, auto_repair=auto_repair)
                if errors == 0:
                    click.echo("[diagnostic] All checks passed!")
                else:
                    click.echo(f"[diagnostic] Completed with {errors} error(s)")
                    raise click.Abort()

        class Diagnostics:
            """
            Centralized diagnostic runner for MilesLib project scaffolds.

            Each diagnostic is defined by a label and a pair of callable strings:
            - Checks must return a (status, message) tuple
            - Repairs are optional and invoked if `--repair` is passed

            Future-proof design:
            - All checks live under Diagnostics.Checks
            - All repairs live under Diagnostics.Repairs
            - Mapping is declarative in Diagnostics.MAP
            """

            DIAGNOSTICS: Dict[str, Dict[str, Callable]] = {}

            MAP: Dict[str, Tuple[str, Optional[str]]] = {
                "Check: _config dir": ("config_dir", "config_dir"),
                "Check: .env file": ("dotenv_file", "dotenv_file"),
                "Check: settings.py": ("settings_file", None),
                "Check: urls.py": ("urls_file", None),
                "Check: global.py": ("global_py", None),
                "Check: AAD settings.py": ("auth_adfs_settings", "auth_adfs_settings"),
            }

            @staticmethod
            def register(label: str, check_fn: Callable, repair_fn: Optional[Callable] = None):
                CLI.Project.Diagnostics.DIAGNOSTICS[label] = {
                    "check": check_fn,
                    "repair": repair_fn,
                }

            @staticmethod
            def run():
                for label, (check_name, repair_name) in CLI.Project.Diagnostics.MAP.items():
                    check_fn = getattr(CLI.Project.Diagnostics.Checks, check_name)
                    repair_fn = getattr(CLI.Project.Diagnostics.Repairs, repair_name) if repair_name else None
                    CLI.Project.Diagnostics.register(label, check_fn, repair_fn)

            @staticmethod
            def run_all(ctx: dict, auto_repair: bool = False) -> int:
                click.echo(f"[diagnostic] Running diagnostics for {ctx['project']} at {ctx['project_path']}")
                errors = 0

                for label, funcs in CLI.Project.Diagnostics.DIAGNOSTICS.items():
                    try:
                        status, msg = funcs["check"](ctx)
                    except Exception as e:
                        status, msg = "fail", f"Check exception: {e}"

                    prefix = {"ok": "[ok]", "warn": "[warn]", "fail": "[fail]"}.get(status, "[?]")
                    click.echo(f"{prefix} {label}: {msg}")

                    if status == "fail":
                        if auto_repair and funcs.get("repair"):
                            try:
                                funcs["repair"](ctx)
                                click.echo(f"[repair] {label} auto-repair attempted.")

                                # Rerun the check after repair
                                status, msg = funcs["check"](ctx)
                                prefix = {"ok": "[ok]", "warn": "[warn]", "fail": "[fail]"}.get(status, "[?]")
                                click.echo(f"{prefix} {label} (after repair): {msg}")
                            except Exception as e:
                                click.echo(f"[repair-fail] {label}: {e}")
                                status = "fail"

                        # Final error count after re-check
                        if status == "fail":
                            errors += 1

                return errors

            class Checks:
                @staticmethod
                def config_dir(ctx):
                    path = ctx["project_path"] / "_config"
                    return ("ok", "_config directory found") if path.exists() else ("fail", "_config directory missing")

                @staticmethod
                def dotenv_file(ctx):
                    path = ctx["project_path"] / "_config" / ".env"
                    return ("ok", ".env file found") if path.exists() else ("fail", ".env file missing")

                @staticmethod
                def settings_file(ctx):
                    path = ctx["project_path"] / f"{ctx['project']}_core" / "settings.py"
                    return ("ok", "settings.py found") if path.exists() else ("fail", "settings.py missing")

                @staticmethod
                def urls_file(ctx):
                    path = ctx["project_path"] / f"{ctx['project']}_core" / "urls.py"
                    return ("ok", "urls.py found") if path.exists() else ("fail", "urls.py missing")

                @staticmethod
                def global_py(ctx):
                    path = ctx["project_path"] / "global.py"
                    return ("ok", "global.py found") if path.exists() else ("fail", "global.py missing")

                @staticmethod
                def auth_adfs_settings(ctx):
                    sp = ctx["project_path"] / f"{ctx['project']}_core" / "settings.py"
                    if not sp.exists():
                        return "fail", "settings.py not found"
                    content = sp.read_text()
                    if "django_auth_adfs" not in content:
                        return "fail", "'django_auth_adfs' not in INSTALLED_APPS"
                    if "AUTH_ADFS" not in content:
                        return "fail", "AUTH_ADFS block missing"
                    return "ok", "AAD config present"

            class Repairs:
                @staticmethod
                def config_dir(ctx):
                    path = ctx["project_path"] / "_config"
                    path.mkdir(parents=True, exist_ok=True)

                @staticmethod
                def dotenv_file(ctx):
                    path = ctx["project_path"] / "_config" / ".env"
                    if not path.exists():
                        path.write_text("DB_HOST=localhost\n")

                @staticmethod
                def auth_adfs_settings(ctx):
                    sp = ctx["project_path"] / f"{ctx['project']}_core" / "settings.py"
                    if not sp.exists():
                        raise FileNotFoundError("settings.py missing")

                    content = sp.read_text()
                    backup = sp.with_name("settings.py.bak")
                    backup.write_text(content)

                    modified = content
                    if "django_auth_adfs" not in content:
                        modified = modified.replace("INSTALLED_APPS = [", "INSTALLED_APPS = [\n    'django_auth_adfs',")

                    if "AUTH_ADFS" not in content:
                        modified += """
        
        # --- Auto-injected by MilesLib diagnostics ---
        AUTH_ADFS = {
            "AUDIENCE": os.getenv("AAD_CLIENT_ID"),
            "CLIENT_ID": os.getenv("AAD_CLIENT_ID"),
            "CLIENT_SECRET": os.getenv("AAD_CLIENT_SECRET"),
            "TENANT_ID": os.getenv("AAD_TENANT_ID"),
            "AUTHORITY": f"https://login.microsoftonline.com/{os.getenv('AAD_TENANT_ID')}",
            "REDIRECT_URI": os.getenv("AAD_REDIRECT_URI", "http://localhost:8000/oauth2/login/"),
            "RELYING_PARTY_ID": os.getenv("AAD_CLIENT_ID"),
            "CLAIM_MAPPING": {"first_name": "given_name", "last_name": "family_name", "email": "upn"},
            "USERNAME_CLAIM": "upn",
            "GROUP_CLAIM": "roles",
            "LOGIN_EXEMPT_URLS": [r"^healthz/$"],
        }
        """
                    sp.write_text(modified)

# Entry point
if __name__ == "__main__":
    CLI().launch()