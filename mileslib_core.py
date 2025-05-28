import builtins
import contextvars
import shutil
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from unittest import mock
from urllib.parse import urlparse

import msal
import pytest
import importlib.util
import requests
import toml
from typing import Any, List, Union, Mapping, Sequence, Callable, Tuple, Type, Optional, Dict
from types import ModuleType, SimpleNamespace
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

import uvicorn
import yaml
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from click import Abort
from click.exceptions import Exit
from dynaconf import Dynaconf
import click
import re
import textwrap
from typing import TYPE_CHECKING
import threading
import inspect

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from jinja2 import Environment, select_autoescape, FileSystemLoader

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import threading
import time
import uvicorn
from functools import wraps
from typing import Callable

if TYPE_CHECKING:
    LOG: Any  # let IDEs think it's there

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
            CLIDecorator to measure and log the execution duration of a function.

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
                    start = time.perf_counter()
                    result = fn(*args, **kwargs)
                    duration = time.perf_counter() - start
                    print(f"[{label}] Completed in {duration:.3f}s")
                    return result

                return wrapper

            return decorator

        @staticmethod
        def recall(fn: Callable, fix: Union[Callable, List[Callable]]):
            """
            Calls a zero-argument function with retry logic and one or more fix strategies.

            This is a wrapper around `attempt()` that enforces callable-based retry behavior.
            If `fix` is a list, each callable will be tried in order as a fallback.

            Args:
                fn (Callable[[], Any]): Zero-arg callable to execute (use lambda for args).
                fix (Callable or list of Callable): One or more fix strategies, all zero-arg callables.

            Returns:
                Any: The result of the successful callable.

            Raises:
                RuntimeError: If all fallback functions fail or a fix callback errors.
                TypeError: If a non-callable is passed to `fix`.
            """
            # simply forward to attempt
            if not callable(fn):
                raise TypeError("First argument to recall() must be callable")
            try:
                if isinstance(fix, list):
                    for fn in fix: StaticMethods.ErrorHandling.attempt(fn, fix=fn)
                elif callable(fix):
                    return StaticMethods.ErrorHandling.attempt(fn, fix=fix)
            except TypeError: raise TypeError

        @staticmethod
        def attempt(
                fn: Callable,
                retries: int = 3,
                fix: Optional[Callable[[], None]] = None,
                backoff_base: Optional[int] = None,
                label: str = "operation",
        ) -> Any:
            """
            Executes a no-argument callable with retry logic, optional fix handler, and timing.

            This function expects that `fn` and `fix` are zero-argument callables.
            If your function requires parameters, wrap it in a `lambda` or use `functools.partial`.

            Args:
                fn (Callable[[], Any]): A zero-argument callable to execute (e.g., lambda: my_func(x)).
                retries (int): Number of retry attempts (default: 3).
                fix (Callable[[], None], optional): One-time recovery callable to run after the first failure.
                backoff_base (int, optional): If set, applies exponential backoff (e.g., 2 = 1s, 2s, 4s).
                label (str): Label for logging and timing context.

            Returns:
                Any: The result of `fn()` if successful.

            Raises:
                RuntimeError: If `fix()` fails or is reused.
                Exception: The last raised exception if all retries fail.
            """
            label = label or getattr(fn, "__name__", "operation")
            timed_fn = StaticMethods.ErrorHandling.timer(label)(fn)
            last_exception = None
            attempted_fix = False

            for attempt in range(1, retries + 1):
                try:
                    result = timed_fn()
                    print(f"[{label}] Success on attempt {attempt}")
                    return result
                except Exception as e:
                    if attempted_fix is True: raise RuntimeError
                    last_exception = e
                    print(f"[{label}] Attempt {attempt}/{retries} failed: {e}")
                    if fix:
                        try:
                            print(f"[{label}] Attempting to fix using {fix}...")
                            fix()
                            attempted_fix = True
                            continue
                        except:
                            print(f"[{label}] Fix failed!")
                            raise RuntimeError
                    if attempt < retries and backoff_base:
                        delay = backoff_base ** (attempt - 1)
                        print(f"[{label}] Retrying in {delay}s...")
                        time.sleep(delay)
                        continue
                    print(f"[{label}] All {retries} attempts failed.")

            raise last_exception

        @staticmethod
        def check_input(arg: Any, expected: Union[Type, Tuple[Type, ...]], label: str = "Input") -> Any:
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
            return arg

    timer = ErrorHandling.timer
    attempt = ErrorHandling.attempt
    recall = ErrorHandling.recall
    check_input = ErrorHandling.check_input
    ERROR_USAGE = """
        StaticMethods ErrorHandling Aliases
        -----------------------------------

        These utility functions are exposed via aliases for convenience:

        timer(label="operation") -> Callable
            CLIDecorator to time and log the execution duration of a function.
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
        """
        Static methods for reading and writing configuration files in multiple formats.
        Supports: TOML, JSON, ENV, YAML, YML, TXT.

        Files are merged if they exist and overwrite is False.
        """
        SUPPORTED_FORMATS = ["txt", "toml", "json", "env", "yml", "yaml"]
        DOTFILE_MAP = {
            ".env": "env",
            ".gitignore": "txt",
            ".dockerignore": "txt",
            ".editorconfig": "ini",
        }

        @staticmethod
        def resolve_extension(path: str | Path) -> str:
            """
            Determines the effective filetype of a given path, including support for dotfiles.

            Args:
                path (str | Path): Path or filename to evaluate.

            Returns:
                str: Inferred filetype (e.g., 'json', 'env', 'txt').

            Raises:
                ValueError: If the filetype is unsupported or cannot be inferred.
            """
            path = Path(path)
            suffix = path.suffix.lstrip(".").lower()
            name = path.name.lower()

            dotfile_map = StaticMethods.FileIO.DOTFILE_MAP
            supported = StaticMethods.FileIO.SUPPORTED_FORMATS + list(dotfile_map.values())

            if suffix and suffix in supported:
                return suffix

            if name in dotfile_map:
                return dotfile_map[name]

            raise ValueError(f"[FileIO] Unsupported or unknown filetype for path: {path}")

        @staticmethod
        def read(path: Path) -> dict | str:
            """
            Reads a configuration file based on its extension and returns parsed content.

            Args:
                path (Path): Path to the file.

            Returns:
                dict | str: Parsed configuration content. TXT returns {'content': str}.

            Raises:
                FileNotFoundError: If the file does not exist.
                ValueError: If file extension is unsupported.
                ImportError: If PyYAML is needed but not installed.
            """
            if not path.exists():
                raise FileNotFoundError(f"[FileIO.read] File not found: {path}")

            ext = StaticMethods.FileIO.resolve_extension(path)

            if ext == "toml":
                import toml
                return toml.load(path)

            elif ext == "json":
                return json.loads(path.read_text(encoding="utf-8"))

            elif ext == "env":
                content = {}
                for line in path.read_text().splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, v = line.split("=", 1)
                        content[k.strip()] = v.strip().strip('"')
                return content

            elif ext in ("yaml", "yml"):
                try:
                    import yaml
                except ImportError:
                    raise ImportError("Install PyYAML to use YAML/YML support.")
                return yaml.safe_load(path.read_text())

            elif ext == "txt":
                return {"content": path.read_text(encoding="utf-8")}

            else:
                raise ValueError(f"[FileIO.read] Unsupported format: {ext}")

        @staticmethod
        def write(
                path: Path,
                data: dict | str,
                overwrite: bool = False,
                replace_existing: bool = False,
                section: str = None
        ):
            """
            Writes configuration data to a file, optionally merging with existing contents.
            Accepts both dict and str. All formats go through centralized logic.

            Args:
                path (Path): Target file path.
                ext (str): File extension (e.g., 'json', 'toml', 'env', 'yml', 'txt').
                data (dict | str): Content to write. Must be a dict or str depending on format.
                overwrite (bool): If True, ignore existing file contents.
                replace_existing (bool): Whether to replace existing keys during merge.
                section (str): For structured formats, write under this section if provided.

            Raises:
                ValueError: For unsupported formats or malformed inputs.
                ImportError: If PyYAML is missing for .yml/.yaml.
            """
            ext = StaticMethods.FileIO.resolve_extension(path)

            if ext not in StaticMethods.FileIO.SUPPORTED_FORMATS:
                raise ValueError(f"[FileIO] Unsupported file extension: .{ext}")

            path.parent.mkdir(parents=True, exist_ok=True)

            # Normalize string input
            if isinstance(data, str):
                if ext == "txt":
                    data = {"content": data}
                elif ext == "env":
                    lines = data.strip().splitlines()
                    data = {
                        k.strip(): v.strip().strip('"')
                        for k, v in (line.split("=", 1) for line in lines if "=" in line)
                    }
                elif ext in ("toml", "json", "yaml", "yml"):
                    try:
                        data = json.loads(data)
                        if not isinstance(data, dict):
                            raise ValueError(f"[FileIO] String must serialize to dict for .{ext}")
                    except json.JSONDecodeError as e:
                        raise ValueError(f"[FileIO] String content for .{ext} must be valid JSON: {e}")
                else:
                    raise ValueError(f"[FileIO] Cannot use str input with unsupported format: .{ext}")

            if not isinstance(data, dict):
                raise TypeError(f"[FileIO] Final data must be a dict for .{ext}, got {type(data)}")

            merged_data = {}

            if not overwrite and path.exists():
                existing = StaticMethods.FileIO.read(path)

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
                if not isinstance(merged_data, dict) or "content" not in merged_data:
                    raise ValueError("TXT write requires {'content': str}")
                path.write_text(merged_data["content"], encoding="utf-8")

        @staticmethod
        def _merge(base: dict, new: dict, replace: bool = False) -> dict:
            """
            Merges two dictionaries with optional key replacement.

            Args:
                base (dict): Original dictionary to merge into.
                new (dict): New dictionary to merge.
                replace (bool): Whether to replace existing keys.

            Returns:
                dict: Merged result.
            """
            merged = base.copy()
            for k, v in new.items():
                if k not in merged or replace:
                    merged[k] = v
            return merged

        @staticmethod
        @staticmethod
        def ensure_file_with_default(
                path: str | Path,
                default: dict | str,
                encoding: str = "utf-8"
        ) -> Path:
            """
            Ensures the file at `path` exists and is non-empty. If not, writes `default` content.
            Supports toml, json, yaml/yml, env, and txt formats.

            Args:
                path (str | Path): Path to the file.
                default (dict | str): Content to write if file is empty or missing.
                encoding (str): File encoding (for plain text).

            Returns:
                Path: Validated path.

            Raises:
                TypeError: If default type is invalid.
                ValueError: If extension unsupported.
                OSError: If write fails.
            """
            path = Path(path)
            ext = StaticMethods.FileIO.resolve_extension(path)

            if ext not in StaticMethods.FileIO.SUPPORTED_FORMATS:
                raise ValueError(f"[FileIO] Unsupported file extension: .{ext}")

            if path.exists():
                if ext in ["txt", "env"] and path.read_text(encoding=encoding).strip() == "":
                    print(f"[FileIO] {path} exists but is empty, overwriting...")
                elif path.stat().st_size > 0:
                    print(f"[FileIO] {path} already exists and is non-empty, skipping write.")
                    return path
            else:
                print(f"[FileIO] {path} does not exist. Will create it.")

            path.parent.mkdir(parents=True, exist_ok=True)

            try:
                # Write dicts
                if isinstance(default, dict):
                    for k, v in default.items():
                        if v is None:
                            default[k] = ""
                    print(f"[FileIO] Writing dict to {path}:\n{json.dumps(default, indent=2)}")
                    if ext == "env":
                        default = {k: str(v) for k, v in default.items()}
                        StaticMethods.FileIO.write(path, data=default, overwrite=True)
                    elif ext == "toml":
                        path.write_text(toml.dumps(default), encoding=encoding)
                    elif ext == "json":
                        path.write_text(json.dumps(default, indent=2), encoding=encoding)
                    elif ext in ("yaml", "yml"):
                        import yaml
                        path.write_text(yaml.safe_dump(default, sort_keys=False), encoding=encoding)
                    elif ext == "txt":
                        path.write_text(str(default), encoding=encoding)
                    else:
                        raise ValueError(f"[FileIO] Cannot write dict to unknown format: {ext}")

                # Write strings
                elif isinstance(default, str):
                    if ext == "txt":
                        print(f"[FileIO] Writing plain text to {path}:\n{default}")
                        path.write_text(default, encoding=encoding)
                    elif ext == "env":
                        lines = default.strip().splitlines()
                        env_dict = {
                            k.strip(): v.strip().strip('"')
                            for k, v in (line.split("=", 1) for line in lines if "=" in line)
                        }
                        print(f"[FileIO] Writing parsed ENV string to {path}:\n{json.dumps(env_dict, indent=2)}")
                        StaticMethods.FileIO.write(path, data=env_dict, overwrite=True)
                    else:
                        print(f"[FileIO] Writing raw string to {path}:\n{default}")
                        path.write_text(default, encoding=encoding)

                else:
                    raise TypeError("[FileIO] Default must be a dict or str.")

                print(f"[FileIO] Successfully wrote default content to {path}")

            except Exception as e:
                raise OSError(f"[FileIO] Failed to write to '{path}': {e}")

            return path

    read = FileIO.read
    write = FileIO.write
    ensure_file_with_default = FileIO.ensure_file_with_default

sm = StaticMethods

# ─── Root Directory ──────────────────────────────────────────────
GLOBAL_ROOT = Path(os.getcwd()).resolve()

# ─── Config and Log Paths ────────────────────────────────────────
GLOBAL_CFG_FILE = GLOBAL_ROOT / "mileslib_settings.toml"
GLOBAL_CFG_FILE.parent.mkdir(parents=True, exist_ok=True)  # Ensure config dir exists
GLOBAL_LOG_DIR = GLOBAL_ROOT / "logs"
GLOBAL_LOG_DIR.mkdir(parents=True, exist_ok=True)  # Ensure log dir exists
GLOBAL_TEMPLATES_DIR = GLOBAL_ROOT / "templates"

# ─── Environment Paths ───────────────────────────────────────────
DEF_ENV = GLOBAL_ROOT / ".env"
SEL_ENV = None
ENV = SEL_ENV if SEL_ENV is not None else DEF_ENV

# ─── Default ENV Content ─────────────────────────────────────────
ENV_CONTENT = {
    "global_root": str(GLOBAL_ROOT),
    "global_cfg_file": str(GLOBAL_CFG_FILE),
    "global_log_folder": str(GLOBAL_LOG_DIR),
    "selected_project": ""
}

# ─── Default Global Config Values ───────────────────────────────
GLOBAL_CFG_DEFAULT = {
    "selected_project": None,
    "template_directory": str(GLOBAL_TEMPLATES_DIR)
}

project_name = None
project_root = None

PROJECT_CFG_DEFAULT = {
    "project_name": project_name,
    "project_root": project_root,
    "database": {
        "host": "localhost",
        "port": "5432",
        "name": "",
        "user": "",
        "password": "",
    },
    "aad": {
        "server": "",
        "client_id": "",
        "client_secret": "",
        "tenant_id": "",
        "scopes": "User.Read openid profile offline_access",
        "authority": "https://login.microsoftonline.com/${AAD_TENANT_ID}",
    },
}

# ─── Required Keys for Validation ──────────────────────────────
GLOBAL_CFG_ENSURE_LIST = list(GLOBAL_CFG_DEFAULT.keys())
PROJECT_CFG_ENSURE_LIST = list(PROJECT_CFG_DEFAULT.keys())
DENY_LIST: list = ["", None, "null", "NULL", "None", "missing", "undefined", "todo"]

thread_local = threading.local()
thread_local.hijack_depth = 0

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
        def setup(path=None):
            path = path or ENV

            if path is None:
                raise ValueError("[EnvLoader.setup] Path resolution failed — 'path' is None.")

            env_path = sm.ensure_file_with_default(path, ENV_CONTENT)
            print(f"[ensure_file_with_default] Writing to {path}")
            if not env_path.exists():
                raise RuntimeError(f".env failed to initialize at {env_path}")

            print(f"[debug] Successfully created or validated: {env_path}")
            return env_path

        @staticmethod
        def load_env(path: Path = ENV) -> dict:
            """
            Loads environment variables from .env file, ensuring it exists first.

            Returns:
                dict: Loaded environment variables

            Raises:
                RuntimeError: If .env file creation or parsing fails
            """
            path = path or ENV

            def try_read():
                return sm.read(path)

            def try_setup():
                return MilesContext.EnvLoader.setup(path)

            if MilesContext.EnvLoader._cache:
                return MilesContext.EnvLoader._cache

            env_dict = sm.recall(try_read, try_setup)

            if not path.exists():
                raise FileNotFoundError(f"[EnvLoader] .env file does not exist after setup: {path}")
            if not env_dict:
                raise TypeError(f"[EnvLoader] Issue with env parsing: {env_dict}")

            MilesContext.EnvLoader._cache = env_dict
            MilesContext.EnvLoader._env_path = path
            return env_dict

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
                env_data = sm.read(env_path) if env_path.exists() else {}
                if key in env_data:
                    del env_data[key]
                    sm.write(
                        path=env_path,
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
            env = MilesContext.EnvLoader._cache or MilesContext.EnvLoader.load_env(
                getattr(MilesContext.EnvLoader, "_env_path", ENV))
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
            env = MilesContext.EnvLoader._cache or MilesContext.EnvLoader.load_env(
                getattr(MilesContext.EnvLoader, "_env_path", ENV))
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
        @staticmethod
        def configify(data: dict) -> dict:
            """
            Recursively convert all values in a dictionary to strings.
            Useful for sanitizing configuration values before serialization.

            Args:
                data (dict): The input dictionary with arbitrary value types.

            Returns:
                dict: A new dictionary with the same structure but all values as strings.

            Raises:
                TypeError: If input is not a dictionary.
            """
            if not isinstance(data, dict):
                raise TypeError("configify expects a dictionary")

            def stringify(val):
                if isinstance(val, dict):
                    return {k: stringify(v) for k, v in val.items()}
                elif isinstance(val, list):
                    return [stringify(v) for v in val]
                elif isinstance(val, tuple):
                    return tuple(stringify(v) for v in val)
                else:
                    return str(val)

            return {k: stringify(v) for k, v in data.items()}

        @staticmethod
        def build(path):
            default = None
            file = None
            try:
                if Path(path).resolve() == Path(GLOBAL_CFG_FILE).resolve():
                    default = GLOBAL_CFG_DEFAULT
                    file = sm.ensure_file_with_default(path, default)
                else:
                    default = PROJECT_CFG_DEFAULT
                    file = sm.ensure_file_with_default(path, default)
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
                lambda: MilesContext.Config.dump(path),  # <- primary attempt
                lambda: MilesContext.Config.build(path)  # <- fallback / fix
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
            data = MilesContext.Config.dump(path=path)
            return data

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

            sm.write(path=path, data=data, overwrite=True)

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
            if path is GLOBAL_CFG_FILE:
                e = GLOBAL_CFG_ENSURE_LIST + (ensure or [])
            else:
                e = (ensure or [])
            d = DENY_LIST + (deny or [])
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

    cfg_get = Config.get
    cfg_write = Config.write
    cfg_validate = Config.validate

    # ─── Hierarchical Call Stack Tracking ─────────────────────────────────────────

    # A context variable holding the current call‐stack as a list of function names
    _call_stack = contextvars.ContextVar("_call_stack", default=[])

    @contextmanager
    def log_func(name: str):
        """
        Context manager to push/pop a function name onto the call stack.
        """
        stack = MilesContext._call_stack.get()
        token = MilesContext._call_stack.set(stack + [name])
        try:
            yield
        finally:
            MilesContext._call_stack.reset(token)

    def _enrich_record(record):
        """
        Loguru patch function: injects extra['func'] = dot-joined call stack.
        """
        stack = MilesContext._call_stack.get()
        record["extra"]["func"] = ".".join(stack) if stack else ""
        return record

    # ─── Logger Utility ───────────────────────────────────────────────────────────

    class Logger:
        """
        Logger utility using loguru with UUID‐tagged session identity.
        Adds a patch to include hierarchical func names in every record.
        """

        _configured = False
        _uuid = None
        _logger = None
        _log_path = None
        _handler_ids = SimpleNamespace(file=None, console=None)

        @staticmethod
        def try_import_loguru():
            try:
                import loguru
            except ImportError as e:
                raise ImportError("loguru is required for Logger but not installed.") from e
            return loguru

        @staticmethod
        def init_logger(
                log_dir: Path = Path("logs"),
                label: str = None,
                serialize: bool = False,
                pretty_console: bool = True,
                level: str = "INFO",
        ):
            """
            Initialize the loguru logger with optional file and console output.
            Logs include a hierarchical func name from the call stack.
            """
            if MilesContext.Logger._configured:
                return MilesContext.Logger._logger

            loguru = MilesContext.Logger.try_import_loguru()
            logger = loguru.logger

            # One‐time configuration
            MilesContext.Logger._uuid = str(uuid.uuid4())
            MilesContext.Logger._configured = True

            # Ensure log directory exists
            log_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
            suffix = f"__{label}" if label else f"__{MilesContext.Logger._uuid}"
            log_file = log_dir / f"{timestamp}{suffix}.log"
            MilesContext.Logger._log_path = log_file

            # Remove default handlers
            logger.remove()

            # Patch to enrich each record with our call stack (pass the function, don’t call it)
            logger = logger.patch(MilesContext._enrich_record)

            # Format: time | LEVEL | func.hierarchy | message
            fmt = (
                "<green>{time:HH:mm:ss.SSS}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{extra[func]}</cyan> | "
                "{message}"
            )

            # Console handler
            if pretty_console:
                MilesContext.Logger._handler_ids.console = logger.add(
                    sys.stderr, level=level, colorize=True, enqueue=True, format=fmt
                )

            # File handler
            MilesContext.Logger._handler_ids.file = logger.add(
                str(log_file), level=level, serialize=serialize, enqueue=True, format=fmt
            )
            # Initial debug
            logger.debug("[Logger Init] UUID={} → {}", MilesContext.Logger._uuid, log_file)
            MilesContext.Logger._logger = logger
            return logger

        @staticmethod
        def get_loguru():
            if not MilesContext.Logger._configured:
                raise RuntimeError("Logger has not been initialized.")
            return MilesContext.Logger._logger

        @staticmethod
        def diagnostics():
            print("Logger Diagnostics:")
            print(f"  UUID:       {MilesContext.Logger._uuid}")
            print(f"  Configured: {MilesContext.Logger._configured}")
            print(f"  Log Path:   {MilesContext.Logger._log_path}")
            print(f"  Handlers:   console={MilesContext.Logger._handler_ids.console}, file={MilesContext.Logger._handler_ids.file}")

        @staticmethod
        def reset():
            if MilesContext.Logger._logger:
                MilesContext.Logger._logger.remove()
            MilesContext.Logger._configured = False
            MilesContext.Logger._uuid = None
            MilesContext.Logger._logger = None
            MilesContext.Logger._log_path = None
            MilesContext.Logger._handler_ids = SimpleNamespace(file=None, console=None)

    class AsyncCallbacks:
        """
        Temporary FastAPI-based async callback server for OAuth or webhook-like flows.
        Can be used as a decorator to pause function execution until a callback is received.
        """

        _app = FastAPI()
        _lock = threading.Lock()
        _result = None
        _triggered = False
        _server_thread = None

        @staticmethod
        def async_callback(path: str = "/callback", timeout: float = 60):
            """
            Decorator to enable temporary FastAPI callback for async flows (e.g. OAuth).
            Blocks execution until a GET request hits the specified path.

            Args:
                path (str): Endpoint path to register for callback (default /callback)
                timeout (float): Max seconds to wait for the callback before proceeding

            Returns:
                Callable: Decorator that pauses function execution until callback received
            """

            def decorator(fn: Callable[[dict], None]):
                @wraps(fn)
                def wrapper(*args, **kwargs):
                    with MilesContext.AsyncCallbacks._lock:
                        if not MilesContext.AsyncCallbacks._server_thread:
                            @MilesContext.AsyncCallbacks._app.get(path)
                            async def callback(req: Request):
                                MilesContext.AsyncCallbacks._result = dict(req.query_params)
                                MilesContext.AsyncCallbacks._triggered = True
                                return JSONResponse({"status": "received"})

                            MilesContext.AsyncCallbacks._server_thread = threading.Thread(
                                target=lambda: uvicorn.run(
                                    MilesContext.AsyncCallbacks._app,
                                    host="127.0.0.1",
                                    port=8000,
                                    log_level="error"
                                ),
                                daemon=True
                            )
                            MilesContext.AsyncCallbacks._server_thread.start()
                            print(f"[AsyncCallbacks] Waiting for callback on {path}...")

                    start = time.time()
                    while not MilesContext.AsyncCallbacks._triggered and (time.time() - start < timeout):
                        time.sleep(0.5)

                    if not MilesContext.AsyncCallbacks._triggered:
                        print(f"[AsyncCallbacks] Timeout waiting for callback at {path}")

                    return fn(MilesContext.AsyncCallbacks._result or {}, *args, **kwargs)

                return wrapper

            return decorator

    class Decorator:
        """
        MilesLib-compatible decorator with full log capture for print/echo,
        retry/fix, timed, safe modes, and hierarchical func-name context.
        """

        @staticmethod
        def mileslib(
                *,
                retry: bool = False,
                fix: Optional[Union[callable, list]] = None,
                timed: bool = True,
                logged: bool = True,
                safe: bool = True,
                env: bool = True,
                callback: Optional[str] = None,
                label: Optional[str] = None,
        ):
            def decorator(fn):
                # Unwrap staticmethod/classmethod
                if isinstance(fn, (staticmethod, classmethod)):
                    fn = fn.__func__
                uid = uuid.uuid4().hex[:8]

                @wraps(fn)
                def wrapper(*args, **kwargs):
                    name = fn.__qualname__
                    with MilesContext.log_func(name):
                        log = MilesContext.Decorator._init_logger()
                        MilesContext.Decorator._hijack_stdout(log, name)
                        MilesContext.Decorator._inject_globals(fn, log)

                        try:
                            if env:
                                MilesContext.Decorator._apply_env_overrides(log, name)
                            MilesContext.Decorator._inject_env_kwargs(fn, kwargs, log)

                            core_fn = MilesContext.Decorator._build_core(
                                fn, args, kwargs, timed, logged, callback, log
                            )

                            if retry:
                                return MilesContext.Decorator._execute_retry(core_fn, fix, name, log)
                            if safe:
                                return MilesContext.Decorator._execute_safe(core_fn, name, log)

                            return core_fn()
                        finally:
                            MilesContext.Decorator._restore_stdout(name)

                return wrapper

            return decorator

        # ─── Helper Methods ─────────────────────────────────────────────────────────

        @staticmethod
        def _init_logger() -> "loguru.Logger":
            """
            Initialize the loguru logger (once) and return it.
            """
            # defined variables
            logger = None

            # logic
            Logger = MilesContext.Logger
            Logger.init_logger()
            logger = Logger.get_loguru()
            logger.debug("[Decorator] Logger initialized")
            return logger

        @staticmethod
        def _hijack_stdout(log, name: str):
            """
            Redirect builtins.print and click.echo to the logger, tracking depth.
            """
            # logic
            depth = getattr(MilesContext.log_func, "_hijack_depth", 0)
            log.debug(f"[{name}] Hijack stdout (depth={depth})")

            if depth == 0:
                MilesContext.log_func._orig_print = builtins.print
                MilesContext.log_func._orig_echo = click.echo
                builtins.print = lambda *a, **k: log.info("{}", " ".join(map(str, a)))
                click.echo = lambda *a, **k: log.info("{}", " ".join(map(str, a)))
            MilesContext.log_func._hijack_depth = depth + 1
            log.debug(f"[{name}] Hijack depth now {MilesContext.log_func._hijack_depth}")

        @staticmethod
        def _restore_stdout(name: str):
            """
            Restore builtins.print and click.echo to their originals.
            """
            log = MilesContext.Logger.get_loguru()
            depth = getattr(MilesContext.log_func, "_hijack_depth", 1) - 1
            log.debug(f"[{name}] Restore stdout (depth={depth})")

            if depth == 0:
                builtins.print = MilesContext.log_func._orig_print
                click.echo = MilesContext.log_func._orig_echo
                delattr(MilesContext.log_func, "_hijack_depth")
                delattr(MilesContext.log_func, "_orig_print")
                delattr(MilesContext.log_func, "_orig_echo")
            else:
                MilesContext.log_func._hijack_depth = depth

            log.debug(f"[{name}] Hijack depth now {depth}")

        @staticmethod
        def _apply_env_overrides(log, name: str):
            """
            Load .env and apply Config overrides, warning on failure.
            """
            # logic
            log.debug(f"[{name}] Applying .env + config overrides")
            MilesContext.EnvLoader.load_env()
            try:
                MilesContext.Config.apply_env(overwrite=True)
            except Exception as e:
                log.warning(f"[{name}] Override failure: {e}")

        @staticmethod
        def _inject_env_kwargs(fn, kwargs: dict, log):
            """
            Inject any cached env vars into kwargs if the function signature accepts them.
            """
            # defined variables
            sig = inspect.signature(fn)
            env_cache = MilesContext.EnvLoader._cache

            # logic
            for k, v in env_cache.items():
                if k in sig.parameters and k not in kwargs:
                    kwargs[k] = v
                    log.debug(f"[{fn.__qualname__}] Injected env var {k}={v}")

        @staticmethod
        def _inject_globals(fn, log):
            try:
                fn.__globals__["log"] = log  # type: ignore
                fn.__globals__["requests_session"] = BackendMethods.Requests.session  # type: ignore
                for k, v in MilesContext.EnvLoader.load_env().items():
                    if k.isidentifier() and k.isupper():
                        fn.__globals__[k] = v  # type: ignore
            except AttributeError:
                log.warning("Function has no __globals__; skipping global injection")

        @staticmethod
        def _build_core(fn, args: tuple, kwargs: dict, timed: bool, logged: bool, callback: Optional[str],
                        log) -> Callable:
            """
            Construct the actual core call logic, including timing, logging, and callbacks.
            """

            # defined sub-function
            def _core():
                # logic
                if logged:
                    log.info(f"[{fn.__qualname__}] Calling with args={args}, kwargs={kwargs}")
                if timed:
                    start = time.perf_counter()

                if callback:
                    @MilesContext.AsyncCallbacks.async_callback(path=callback)
                    def _with_cb(data):
                        log.debug(f"[{fn.__qualname__}] Received callback data: {data}")
                        return fn(*args, **kwargs)

                    result = _with_cb()
                else:
                    result = fn(*args, **kwargs)

                if timed:
                    dur = time.perf_counter() - start
                    log.info(f"[{fn.__qualname__}] Completed in {dur:.3f}s")

                return result

            log.debug(f"[{fn.__qualname__}] Core function constructed")
            return _core

        @staticmethod
        def _execute_retry(core_fn: Callable, fix, name: str, log):
            """
            Run core_fn with retry/fix logic.
            """
            # logic
            log.debug(f"[{name}] Executing with retry (fix={fix})")
            return MilesContext.Decorator._attempt(core_fn, fix, name)

        @staticmethod
        def _execute_safe(core_fn: Callable, name: str, log):
            """
            Run core_fn in safe mode, catching exceptions and returning None on failure.
            """
            # logic
            log.debug(f"[{name}] Executing in safe mode")
            try:
                return core_fn()
            except Exception as e:
                log.exception(f"[{name}] Exception in safe mode: {e}")
                return None

        @staticmethod
        def _attempt(core_fn: Callable[[], Any],
                     fix: Optional[Union[Callable[[], None], List[Callable[[], None]]]],
                     label: str) -> Any:
            """
            Runs core_fn with retries and optional fix logic using StaticMethods.ErrorHandling.
            """
            if fix:
                return StaticMethods.ErrorHandling.recall(core_fn, fix)
            return StaticMethods.ErrorHandling.attempt(core_fn, fix=None, label=label)

    @staticmethod
    def shim(fn: Optional[Callable] = None, **kwargs):
        """
        Supports both @mileslib and @mileslib(...) usage.
        """
        if fn is not None and callable(fn) and not kwargs:
            return MilesContext.Decorator.mileslib()(fn)
        elif fn is None or callable(fn):
            return MilesContext.Decorator.mileslib(**kwargs)
        else:
            raise TypeError("Invalid usage of @mileslib")

mc = MilesContext
mileslib = mc.shim
ROOT = Path(mc.env.get("global_root"))

DEFAULT_PROJECT_NAME = "default_project"
CURRENT_PROJECT_NAME = mc.cfg_get("selected_project")
SEL_PROJECT_NAME = CURRENT_PROJECT_NAME or DEFAULT_PROJECT_NAME
# SEL_PROJECT_PATH = sm.cfg_get
AZURE_CRED = DefaultAzureCredential()

class BackendMethods:
    import threading, time, uvicorn
    from fastapi import FastAPI, Request
    from starlette.responses import JSONResponse
    from functools import wraps
    from typing import Callable

    class Requests:
        """
        Centralized HTTP client with shared session, retries, and logging.

        All methods use the shared `requests.Session` and `@mileslib` for logging, retries, timing, and safe mode.
        """

        # Shared session for connection pooling and cookie reuse
        session = requests.Session()

        @staticmethod
        def _do_request(
                method: str,
                url: str,
                *,
                data=None,
                json=None,
                headers=None,
                timeout: float = 5.0
        ) -> requests.Response:
            """
            Core request logic used by all HTTP wrappers.

            Args:
                method (str): HTTP method name, e.g. 'get', 'post'.
                url (str): Full URL to request.
                data/json (dict): Optional request payload.
                headers (dict): Optional headers.
                timeout (float): Request timeout in seconds.

            Returns:
                Response object, or raises HTTPError.
            """
            sm.try_import("requests")
            sm.check_input(method, str, "method")
            sm.check_input(url, str, "url")

            method = method.lower()
            req = getattr(BackendMethods.Requests.session, method)
            resp = req(url, data=data, json=json, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp

        @staticmethod
        @mileslib(retry=True, timed=True, logged=True)
        def http_get(url: str, retries: int = 3, timeout: float = 5.0) -> requests.Response:
            """
            HTTP GET with retries and decorator integration.

            Args:
                url (str): URL to GET.
                retries (int): Retry attempts.
                timeout (float): Timeout in seconds.

            Returns:
                Response object.
            """
            return sm.attempt(lambda: BackendMethods.Requests._do_request("get", url, timeout=timeout), retries=retries)

        @staticmethod
        @mileslib(retry=True, timed=True, logged=True)
        def http_post(url: str, data: dict, retries: int = 3, timeout: float = 5.0) -> requests.Response:
            """
            HTTP POST with retries and JSON payload.

            Args:
                url (str): URL to POST to.
                data (dict): JSON payload.
                retries (int): Retry attempts.
                timeout (float): Timeout in seconds.

            Returns:
                Response object.
            """
            sm.check_input(data, dict, "data")
            return sm.attempt(lambda: BackendMethods.Requests._do_request("post", url, json=data, timeout=timeout), retries=retries)

        @staticmethod
        @mileslib(retry=True, timed=True, logged=True, safe=True)
        def ensure_endpoint(url: str, timeout: float = 3.0) -> bool:
            """
            Check if an HTTP endpoint is up and responds 2xx or 3xx.

            Args:
                url (str): URL to check.
                timeout (float): Timeout in seconds.

            Returns:
                True if reachable, False otherwise.
            """
            try:
                resp = BackendMethods.Requests._do_request("get", url, timeout=timeout)
                return 200 <= resp.status_code < 400
            except Exception as e:
                print(f"[ensure_endpoint] Request failed: {e}")
                return False

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

bm = BackendMethods

class ProjectAwareGroup(click.Group):
    def format_commands(self, ctx, formatter):
        commands = self.list_commands(ctx)
        if not commands:
            return

        global_cmds, project_grps = [], []
        for name in commands:
            cmd = self.get_command(ctx, name)
            if isinstance(cmd, click.Group) and name in CLIDecorator._projects:
                project_grps.append((name, cmd))
            else:
                global_cmds.append((name, cmd))

        # Global
        if global_cmds:
            with formatter.section("Global Commands"):
                entries = [(n, c.help or "") for n, c in global_cmds]
                try:
                    formatter.write_dl(entries)
                except TypeError:
                    for n, h in entries:
                        formatter.write_text(f"  {n}\t{h}\n")

        # Per-project
        for pname, grp in project_grps:
            with formatter.section(f"Project Commands: {pname}"):
                subs = [(n, c.help or "") for n, c in grp.commands.items()]
                try:
                    formatter.write_dl(subs)
                except TypeError:
                    for n, h in subs:
                        formatter.write_text(f"  {n}\t{h}\n")

class CLIDecorator:
    _global = ProjectAwareGroup(invoke_without_command=True)
    _projects = {}
    _project_only_cmds = []         # ← collect these here

    @staticmethod
    @mileslib
    def auto_register_groups():
        # 1) discover and register each project subgroup
        for sub in ROOT.iterdir():
            cfg = sub / f"mileslib_{sub.name}_settings.toml"
            if not cfg.exists():
                continue

            proj_name = sub.name
            if proj_name not in CLIDecorator._projects:
                @click.group(name=proj_name, cls=ProjectAwareGroup)
                @click.pass_context
                def _grp(ctx):
                    ctx.ensure_object(dict)
                    ctx.obj["project_name"]      = proj_name
                    ctx.obj["project_path"] = sub

                CLIDecorator._projects[proj_name] = _grp
                CLIDecorator._global.add_command(_grp)

        for cmd in CLIDecorator._project_only_cmds:
            for grp in CLIDecorator._projects.values():
                grp.add_command(cmd)

    @staticmethod
    def mileslib_cli(*, project_only: bool = False, **mileslib_kwargs):
        def decorator(fn):
            if isinstance(fn, staticmethod):
                fn = fn.__func__

            # Step A: wrap with your @mileslib
            fn = MilesContext.Decorator.mileslib(**mileslib_kwargs)(fn)

            # Step B: build the Click wrapper that only forwards args your fn wants
            @click.pass_context
            @wraps(fn)
            def wrapper(ctx, *args, **kwargs):
                sig = inspect.signature(fn)
                accepted = set(sig.parameters) - {"ctx"}
                safe_kwargs = {k: v for k, v in kwargs.items() if k in accepted}
                return fn(ctx, *args, **safe_kwargs)

            # Step C: attach click arguments/options
            sig = inspect.signature(fn)
            for param in reversed(list(sig.parameters.values())[1:]):
                ptype = str if param.annotation is inspect._empty else param.annotation
                default = None if param.default is inspect._empty else param.default
                dash = param.name.replace("_", "-")
                if default is None:
                    wrapper = click.argument(param.name, type=ptype)(wrapper)
                else:
                    wrapper = click.option(f"--{dash}", default=default, type=ptype)(wrapper)

            # Step D: turn into a Click command
            cmd_name = fn.__name__.replace("_", "-")
            command = click.command(name=cmd_name, help=fn.__doc__)(wrapper)

            if project_only:
                # collect it for later
                CLIDecorator._project_only_cmds.append(command)
            else:
                # immediately stick it in the global group
                CLIDecorator._global.add_command(command)

            return command

        return decorator


# alias so your decorators don’t change:
mileslib_cli = CLIDecorator.mileslib_cli

class CLI:
    """
    MilesLib CLI orchestrator.
    """
    def __init__(self):
        # also in case someone does CLI().entry() directly
        CLIDecorator.auto_register_groups()
        self.cli = CLIDecorator._global

    @mileslib
    def entry(self):
        # no custom argv logic—let Click do the routing
        return self.cli()

    class CMDManager:
        class Global:
            class InitializeProject:
                @staticmethod
                @mileslib_cli(project_only=False)  # or True, depending on scope
                def init_project(ctx, project_name: str):
                    """
                    Initializes a new project folder with Django scaffold and config.

                    Args:
                        project_name (str): Name of the project.

                    Raises:
                        click.Abort: On validation or subprocess failure.
                    """

                    # ─── Path Setup ─────────────────────────────────────────────
                    try:
                        root = sm.validate_directory(ROOT / project_name)
                        proj_root = sm.validate_directory(root)
                        proj_str = str(proj_root)
                    except Exception as e:
                        print(f"[init] Directory validation failed: {e}")
                        raise click.Abort()

                    cfg_path = root / f"mileslib_{project_name}_settings.toml"
                    cfg = mc.Config.build(cfg_path)
                    tests = root / "_tests"
                    django_name = f"{project_name}_core"
                    db_name = f"{project_name}_db"
                    proj_details_list = {
                        "project_name": project_name,
                        "project_root": proj_root,
                        "config_dir": cfg,
                        "tests_dir": tests,
                        "django_project": django_name,
                        "database_name": db_name,
                    }
                    print("[debug] raw proj_details_list:", proj_details_list)
                    proj_details = mc.Config.configify(proj_details_list)

                    # ─── Django ────────────────────────────────────────────────
                    def init_django():
                        print("[init] Starting Django scaffold...")
                        subprocess.run(
                            ["python", "-m", "django", "startproject", django_name, proj_root],
                            check=True
                        )

                    # ─── Folders ───────────────────────────────────────────────
                    def init_folders():
                        for d in [root, tests]:
                            sm.validate_directory(d)

                    # ─── Config (.toml) ─────────────────────────────────────────
                    def init_config():
                        mc.cfg_write(path=cfg, set=proj_details)

                    # ─── Gitignore / Requirements / Readme ──────────────────────
                    def scaffold_basics():
                        (proj_root / ".gitignore").write_text(textwrap.dedent("""\
                            __pycache__/
                            *.pyc
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
                        """), encoding="utf-8")

                        (proj_root / "requirements.txt").write_text(textwrap.dedent("""\
                            #
                            """), encoding="utf-8")

                        (proj_root / "README.md").write_text(f"# {project_name}\n\nInitialized with MilesLib.\n",
                                                             encoding="utf-8")

                    try:
                        init_django()
                        init_folders()
                        init_config()
                        scaffold_basics()
                        print(f"[init] Project '{project_name}' created successfully.")
                    except Exception as e:
                        print(f"[error] Initialization failed: {e}")
                        if root.exists():
                            shutil.rmtree(root)
                        raise click.Abort()

        class Project:
            # FastAPI callback listener and nested AzureBootstrap
            app = FastAPI()

            class AzureBootstrap:
                tenant_id = None
                client_id = None
                redirect_uri = None
                required = ["tenant_id", "client_id", "redirect_uri"]

                @staticmethod
                @mileslib_cli(project_only=True)
                def azure_bootstrap(ctx):
                    """
                    Bootstraps an Azure AD application using the project_name's config.
                    """
                    #Top-Level Vars
                    project_name = ctx.obj["project_name"]
                    proj_path = ctx.obj["project_path"]
                    cfg_path = proj_path / f"mileslib_{project_name}_settings.toml"
                    ab = CLI.CMDManager.Project.AzureBootstrap

                    # Extract AAD settings
                    def get_aad_settings(recall: bool = None) -> dict:
                        sm.ensure_path(cfg_path)
                        settings = {}

                        def print_help_for_tenant_id():
                            """
                            Prints CLI-friendly guidance on how to retrieve your Azure AD Tenant ID.
                            """
                            print("How to find your Azure AD Tenant ID:")
                            print("1. Visit the Azure Active Directory overview page:")
                            print("   👉 https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview")
                            print("2. Look for the 'Tenant ID' field — it will be a GUID (e.g., 12345678-90ab-cdef-1234-567890abcdef).")
                            print("3. Copy and paste it when prompted.")

                        def print_help_for_client_id():
                            """
                            Prints CLI-friendly guidance on how to retrieve your Azure AD Application (Client) ID.
                            """
                            print("How to find your Azure AD Application (Client) ID:")
                            print("1. Open the App Registrations page:")
                            print("   👉 https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade")
                            print("2. Click on the application you've registered (or register a new one).")
                            print("3. Copy the 'Application (client) ID' from the overview page.")
                            print("4. Paste it here when prompted.")

                        def alternatively():
                            print(f"You can also can manually edit the config file here:")
                            print(f"{cfg_path}")
                            print("Under the [aad] section, provide:")
                            print("tenant_id = \"your-tenant-guid\"")
                            print("client_id = \"your-client-id\"")
                            print("redirect_uri = \"http://localhost:8000/callback\"")

                        for k in ab.required:
                            v = None

                            def validate_current_key():
                                ab.ensure_valid_id(key=k, value=v)
                                mc.cfg_write(path=cfg_path, set={"aad": {k: v}})
                                setattr(ab, k, v)
                                settings[k] = v
                                print(f"[aad settings] Validated {k}: {v}")

                            if recall is not True:
                                try:
                                    v = mc.cfg_get("aad", k, path=cfg_path)
                                    validate_current_key()
                                except Exception: v = None

                            if v is None:
                                time.sleep(1)
                                log.error("[aad settings] Your tenant id is invalid or not present!") #type: ignore
                                time.sleep(1)
                                if k == "tenant_id":
                                    print_help_for_tenant_id()
                                elif k == "client_id":
                                    print_help_for_client_id()
                                time.sleep(1)
                                alternatively()
                                time.sleep(1)
                                v = input(f"Please provide your {k}: ").strip()

                            sm.recall(validate_current_key, lambda: get_aad_settings(recall=True))

                            setattr(ab, k, v)
                            print(f"Ensuring valid {k}...")
                            settings[k] = v

                        return settings

                    aad_settings = get_aad_settings()

                    def admin_consent():
                        if not ab.consent_status(project_name):
                            print("Launching admin consent flow...")
                            try:
                                ab.redirect_to_admin_consent(aad_settings)
                                ab.wait_for_callback()
                            except Exception as e:
                                raise RuntimeError(f"Admin consent process failed!: {e}")
                            print("Admin consent granted.")

                    #Ensure Admin Consent Status
                    admin_consent()

                    # 2) App registration
                    print("Registering AAD app '{}'...", project_name)
                    app_id, object_id = ab.AAD.register_app(project_name)
                    print("Registered appId={} objectId={}", app_id, object_id)

                    # 3) Client secret
                    print("Creating client secret for objectId={}...", object_id)
                    secret = ab.AAD.add_client_secret(object_id)

                    # 4) Vault storage
                    print("Storing secrets in vault...")
                    ab.Vault.store_secrets(app_id, secret, tenant_id)

                    click.echo(f"✅ Azure bootstrap complete for '{project_name}'\n  AppId: {app_id}\n  Tenant: {tenant_id}")

                @staticmethod
                def ensure_valid_id(key: str, value: str):
                    """
                    Validates a single Azure AD identifier by checking against Microsoft endpoints.

                    Args:
                        key (str): One of ["tenant_id", "client_id", "redirect_uri"].
                        value (str): The actual value to validate.

                    Raises:
                        RuntimeError: If key is unsupported or the identifier fails validation.
                    """
                    sm.check_input(key, str, "key")
                    sm.check_input(value, str, "value")
                    key = key.lower()

                    if key == "tenant_id":
                        url = f"https://login.microsoftonline.com/{value}/v2.0/.well-known/openid-configuration"
                    elif key == "client_id":
                        url = f"https://graph.microsoft.com/v1.0/applications?$filter=appId eq '{value}'"
                    elif key == "redirect_uri":
                        # Validate scheme + hostname format
                        parsed = urlparse(value)
                        if parsed.scheme not in ("https", "http") or not parsed.netloc:
                            raise RuntimeError(f"[ensure_valid_id] Malformed redirect_uri: {value}")
                        # Just check that the domain resolves at all
                        url = value
                    else:
                        raise RuntimeError(f"[ensure_valid_id] Unsupported identifier type: {key}")

                    if not BackendMethods.Requests.ensure_endpoint(url):
                        raise RuntimeError(f"[ensure_valid_id] Validation failed for {key}: {value}")
                    return True

                @staticmethod
                def consent_status(project_name, update: bool = None) -> bool:
                    """
                    :param update: If marked True or False, updates the env's recognition of consent.
                    :return: bool: Returns update status.
                    """
                    k = f"{project_name}.azurebootstrap_user_has_consented"

                    def update_env():
                        u = str(update)
                        mc.env.write(k, u)
                        return mc.env.get(k)

                    def check_env():
                        dflt = str(False)
                        c = (mc.env.get(k))
                        if c is None:
                            mc.env.write(k, dflt)
                            return dflt
                        return bool(c)

                    if update: return update_env()
                    else: return check_env()

                @staticmethod
                @mileslib(callback="/callback", logged=True)
                def redirect_to_admin_consent(settings: dict):
                    tenant_id = settings["tenant_id"]
                    client_id = settings["client_id"]
                    redirect_uri = settings["redirect_uri"]

                    # Build the consent URL
                    url = (
                        f"https://login.microsoftonline.com/{tenant_id}/adminconsent"
                        f"?client_id={client_id}&redirect_uri={redirect_uri}"
                    )

                    log.info(f"[aad] Opening admin consent flow in browser...") #type: ignore
                    click.launch(url)

                    # This function will pause until GET /callback is hit
                    def handle_callback(data: dict):
                        print(f"[aad] Admin consent granted: {data}")
                        if "tenant" in data:
                            print(f"[aad] Confirmed tenant ID: {data['tenant']}")
                        else:
                            print("[aad] Warning: No tenant ID in callback. Consent may have failed.")

                    return handle_callback  # <-- async_callback wraps this

                class MSALClient:
                    @staticmethod
                    def get_token():
                        tenant = bm.Secrets.get("BOOTSTRAP_TENANT_ID")
                        cid = bm.Secrets.get("BOOTSTRAP_CLIENT_ID")
                        csec = bm.Secrets.get("BOOTSTRAP_CLIENT_SECRET")
                        app = msal.ConfidentialClientApplication(
                            client_id=cid,
                            authority=f"https://login.microsoftonline.com/{tenant}",
                            client_credential=csec
                        )
                        t = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
                        return t.get("access_token")

                class AAD:
                    @staticmethod
                    def register_app(name: str) -> tuple[str, str]:
                        token = CLI.CMDManager.Project.AzureBootstrap.MSALClient.get_token()
                        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
                        payload = {"displayName": name, "signInAudience": "AzureADMyOrg"}
                        resp = bm.http_post("https://graph.microsoft.com/v1.0/applications", payload)
                        data = resp.json()
                        return data["appId"], data["id"]

                    @staticmethod
                    def add_client_secret(obj_id: str) -> str:
                        token = CLI.CMDManager.Project.AzureBootstrap.MSALClient.get_token()
                        payload = {"passwordCredential": {"displayName": "AutoGenSecret"}}
                        resp = bm.http_post(
                            f"https://graph.microsoft.com/v1.0/applications/{obj_id}/addPassword",
                            payload
                        )
                        return resp.json()["secretText"]

                class Vault:
                    @staticmethod
                    def store_secrets(app_id: str, secret: str, tenant_id: str):
                        bm.Secrets.set("aad-app-id", app_id)
                        bm.Secrets.set("aad-app-secret", secret)
                        bm.Secrets.set("aad-tenant-id", tenant_id)

                class Registry:
                    tenants_db = {}

                    @staticmethod
                    def update(tenant_id: str):
                        CLI.CMDManager.Project.AzureBootstrap.Registry.tenants_db[tenant_id] = {
                            "consented": True,
                            "created_at": datetime.utcnow().isoformat(),
                            "apps": []
                        }

            @app.get("/callback", response_model=None)
            def handle_callback(request: Request):
                if request.query_params.get("admin_consent") == "True":
                    tid = request.query_params.get("tenant")
                    CLI.CMDManager.Project.AzureBootstrap.Registry.update(tid)
                    return PlainTextResponse("Consent successful! Close this window.")
                return PlainTextResponse("Consent failed or denied.")

            class DockerSetup:
                """
                Handles Docker-based service scaffolding and container management for MilesLib projects.
                Supports PostgreSQL and future add-ons like Redis, pgAdmin, Celery, etc.
                """

                @staticmethod
                @mileslib_cli(project_only=True)
                def docker_setup(ctx):
                    """
                    CLI entrypoint for scaffolding and launching Docker-based infrastructure for the project.

                    Responsibilities:
                    - Creates `docker-compose.yml` with service blocks for PostgreSQL, Redis, and optional Flower.
                    - Generates a `.env` file populated with project-specific environment variables.
                    - Validates Docker availability and prompts to start services.
                    - Provides instructions for managing Docker containers via CLI.

                    Args:
                        ctx (click.Context): Click context, should contain project_name and project_path.

                    Side Effects:
                        - Writes `docker-compose.yml` and `.env` to the project directory.
                        - Starts containers using `docker-compose up -d`.
                        - Logs success or error messages for service initialization.

                    """

                @staticmethod
                def generate_compose_file(project_name: str, output_path: Path, settings: dict):
                    """
                    Writes a docker-compose.yml to the given output path using provided DB settings.

                    Args:
                        project_name (str): The name of the project (used in container names).
                        output_path (Path): The directory where the docker-compose.yml should be created.
                        settings (dict): Must include db_name, db_user, db_pass.

                    Side Effects:
                        - Creates docker-compose.yml file in output_path.
                    """

                @staticmethod
                def generate_compose_file(project_name: str, output_path: Path, settings: dict):
                    """
                    Writes a docker-compose.yml to the given output path using provided DB settings.

                    Args:
                        project_name (str): The name of the project (used in container names).
                        output_path (Path): The directory where the docker-compose.yml should be created.
                        settings (dict): Must include db_name, db_user, db_pass.

                    Side Effects:
                        - Creates docker-compose.yml file in output_path.
                    """

                @staticmethod
                def generate_env_file(output_path: Path, settings: dict):
                    """
                    Writes a .env file with database environment variables used by Docker.

                    Args:
                        output_path (Path): Directory where the .env file should be saved.
                        settings (dict): Contains DB credentials and project-specific environment values.

                    Side Effects:
                        - Creates or overwrites .env file.
                    """

                @staticmethod
                def start_docker_services(project_path: Path, services: list[str] = None):
                    """
                    Runs `docker-compose up -d` in the project path to start the desired services.

                    Args:
                        project_path (Path): Path to the root of the MilesLib project.
                        services (list[str], optional): Services to start. Defaults to ['db'].

                    Raises:
                        subprocess.CalledProcessError if Docker fails to start.
                    """

                @staticmethod
                def stop_docker_services(project_path: Path, services: list[str] = None):
                    """
                    Stops running Docker containers for the given services.

                    Args:
                        project_path (Path): Path to the project directory.
                        services (list[str], optional): Services to stop. Defaults to ['db'].
                    """

                @staticmethod
                def remove_docker_services(project_path: Path):
                    """
                    Stops and removes all Docker containers, networks, and volumes created by the project.

                    Args:
                        project_path (Path): Path to the root project directory with docker-compose.yml.

                    Raises:
                        subprocess.CalledProcessError if teardown fails.
                    """

                @staticmethod
                def check_postgres_ready(timeout: float = 10.0) -> bool:
                    """
                    Checks whether PostgreSQL is available and accepting connections on localhost:5432.

                    Args:
                        timeout (float): Timeout in seconds to wait for readiness.

                    Returns:
                        bool: True if PostgreSQL is reachable, False otherwise.
                    """

            class DjangoSetup:
                """
                Handles Django-specific setup for MilesLib projects:
                - Injects PostgreSQL settings into Django's settings.py
                - Scaffolds Azure AD (MSAL) authentication
                - Ensures required apps, middlewares, and auth backends are added
                """

                @staticmethod
                def inject_postgres_settings(settings_path: Path, db_settings: dict):
                    """
                    Modifies the Django `settings.py` file to configure PostgreSQL.

                    Args:
                        settings_path (Path): Path to the Django settings.py file.
                        db_settings (dict): Dictionary containing db_name, db_user, db_pass, host, port.

                    Side Effects:
                        - Replaces existing DATABASES config with PostgreSQL block.
                        - Writes changes in-place to settings.py.
                    """

                @staticmethod
                def add_msal_integration(settings_path: Path, project_root: Path):
                    """
                    Adds MSAL configuration to Django settings and scaffolds necessary MSAL logic.

                    Args:
                        settings_path (Path): Path to the Django settings.py file.
                        project_root (Path): Root directory of the Django project.

                    Side Effects:
                        - Adds AAD client ID, tenant ID, redirect URI to settings.py.
                        - Adds `django_microsoft_auth` or custom backend if required.
                        - Optionally creates auth views / urls / middleware hooks.
                    """

                @staticmethod
                def ensure_required_apps(settings_path: Path):
                    """
                    Ensures `INSTALLED_APPS` includes needed packages for DB and MSAL integration.

                    Args:
                        settings_path (Path): Path to settings.py.

                    Side Effects:
                        - Adds entries like 'django.contrib.sites', 'microsoft_auth', etc.
                    """

                @staticmethod
                def inject_auth_backends(settings_path: Path):
                    """
                    Appends required auth backends (e.g., Microsoft AAD) to `AUTHENTICATION_BACKENDS`.

                    Args:
                        settings_path (Path): Path to settings.py.

                    Side Effects:
                        - Adds 'microsoft_auth.backends.MicrosoftAuthenticationBackend'
                          or your custom backend.
                    """

                @staticmethod
                def create_msal_login_urls(project_root: Path):
                    """
                    Creates Django URL routes and view stubs for handling MSAL login, callback, and logout.

                    Args:
                        project_root (Path): Root of the Django app (where urls.py and views.py exist).

                    Side Effects:
                        - Adds login/logout/callback URL patterns to urls.py.
                        - Creates views.py entries or MSAL-compatible templates if not present.
                    """

                @staticmethod
                def set_env_settings_reference(settings_path: Path):
                    """
                    Modifies `settings.py` to reference secrets/env variables from MilesContext.

                    Args:
                        settings_path (Path): Path to settings.py.

                    Side Effects:
                        - Replaces hardcoded credentials with `os.getenv()` or `MilesContext.secrets.get()`.
                    """

            class BackgroundTasks:
                """
                Handles background task infrastructure for MilesLib projects using Celery, Redis, and optionally Flower.

                Responsibilities:
                - Generates celery.py and tasks.py in the project root
                - Adds Redis to docker-compose
                - Adds optional Flower monitoring UI
                - Injects Django or FastAPI-compatible Celery config
                """

                @staticmethod
                @mileslib_cli(project_only=True)
                def setup_background_tasks(ctx):
                    """
                    CLI entrypoint for setting up background task infrastructure with Celery and Redis.

                    Responsibilities:
                    - Generates `celery.py` and `tasks.py` in the Django/FastAPI project root.
                    - Adds Redis service block to `docker-compose.yml`.
                    - Optionally adds Flower service for task monitoring.
                    - Patches settings file with Celery broker/backend config.
                    - Ensures required .env variables are defined.

                    Args:
                        ctx (click.Context): Click context, expected to contain project_name and project_path.

                    Side Effects:
                        - Writes or modifies local project files and environment config.
                        - Registers Celery for asynchronous background task execution.
                        - Enables Redis-backed broker and optional Flower monitoring.
                    """

                def scaffold_celery_files(project_root: Path, project_name: str):
                    """
                    Writes `celery.py` and `tasks.py` boilerplate files in the Django project directory.

                    Args:
                        project_root (Path): Path to root of the project.
                        project_name (str): Name of the Django project to bind Celery to.

                    Side Effects:
                        - Creates celery.py entrypoint with app init.
                        - Creates tasks.py with basic example task.
                        - Adds Celery app loading in __init__.py if needed.
                    """

                @staticmethod
                def patch_settings_for_celery(settings_path: Path):
                    """
                    Modifies Django `settings.py` or FastAPI equivalent to support Celery broker and backend.

                    Args:
                        settings_path (Path): Path to the project settings.py.

                    Side Effects:
                        - Injects CELERY_BROKER_URL and CELERY_RESULT_BACKEND from env or secrets.
                        - Adds necessary Celery imports if missing.
                    """

                @staticmethod
                def add_redis_to_docker_compose(compose_path: Path):
                    """
                    Injects Redis service block into the docker-compose.yml.

                    Args:
                        compose_path (Path): Path to docker-compose.yml

                    Side Effects:
                        - Adds 'redis' service if not already present.
                        - Mounts a volume if needed.
                    """

                @staticmethod
                def add_flower_to_docker_compose(compose_path: Path):
                    """
                    Adds Flower service for real-time Celery monitoring.

                    Args:
                        compose_path (Path): Path to docker-compose.yml

                    Side Effects:
                        - Adds 'flower' service (port 5555).
                        - Links to Redis and Celery app.
                    """

                @staticmethod
                def create_env_entries(env_path: Path):
                    """
                    Ensures .env file contains required Celery/Redis environment variables.

                    Args:
                        env_path (Path): Path to the .env file.

                    Side Effects:
                        - Adds default CELERY_BROKER_URL, RESULT_BACKEND, and Flower settings.
                    """

                @staticmethod
                def test_celery_connection(project_root: Path):
                    """
                    Runs a one-off test to ensure Celery worker can connect to Redis and run tasks.

                    Args:
                        project_root (Path): Root path to where celery.py and tasks.py exist.

                    Raises:
                        RuntimeError if connection or task execution fails.
                    """

            class FrontDoorSetup:
                """
                Handles Azure Front Door setup and integration with external DNS providers like GoDaddy.
                Enables HTTPS, domain validation, and CNAME binding for custom domains.
                """

                @staticmethod
                @mileslib_cli(project_only=True)
                def setup_godaddy_dns(domain: str, subdomain: str = "www"):
                    """
                    Guides the user through configuring GoDaddy DNS to point a custom domain or subdomain
                    (e.g. www.yourdomain.com) to an Azure Front Door instance.

                    Args:
                        domain (str): The root domain managed by GoDaddy (e.g., "yourdomain.com").
                        subdomain (str, optional): The subdomain to configure (e.g., "www", "api"). Defaults to "www".

                    Side Effects:
                        - Prompts the user to create a CNAME pointing to Azure Front Door.
                        - Prompts the user to add a TXT record for domain validation.
                        - Instructs user to verify domain ownership and enable HTTPS in Azure.
                    """
                    pass

def main():
    # make sure groups exist *before* Click ever parses
    CLIDecorator.auto_register_groups()
    CLI().entry()

if __name__ == "__main__":
    main()