import builtins
import shutil
import uuid
from contextvars import ContextVar
from functools import wraps
from unittest import mock
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
import yaml
from click import Abort
from click.exceptions import Exit
from dynaconf import Dynaconf
import click
import re
import textwrap
from typing import TYPE_CHECKING
import threading
import inspect

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
            print(f"[FileIO] Reading {ext} config from {path}")

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
                raise ValueError(f"[FileIO.read] Unsupported config format: {ext}")

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
            print(f"[FileIO] Writing {ext} config to {path}")

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
                print("[FileIO] File exists — merging data")
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
            print(f"[FileIO] Merging config: replace_existing={replace}")
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

PROJECT_CFG_DEFAULT = {
    "project_name": "",
    "project_root": "",
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
            print(f"[debug] Running setup with: {path} (type: {type(path)})")

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
                print(f"[debug] Attempting to read env at: {path}")
                return sm.read(path)

            def try_setup():
                print(f"[debug] Attempting to create env at: {path}")
                return MilesContext.EnvLoader.setup(path)

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
        def build(path):
            default = None
            file = None
            try:
                if Path(path).resolve() == Path(GLOBAL_CFG_FILE).resolve():
                    default = GLOBAL_CFG_DEFAULT
                    file = sm.ensure_file_with_default(path, default)
                else:
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
            data = MilesContext.Config.dump(path=path)
            print(f"[cfg.get] Full config content: {data}")
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

    class Logger:
        """
        Logger utility using loguru with UUID-tagged session identity.
        Prevents multiple handler attachments and tracks log instances.
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

            Args:
                log_dir (Path): Directory to write log files into.
                label (str): Optional label suffix for log filename.
                serialize (bool): Whether to serialize log output to JSON.
                pretty_console (bool): Whether to include console output.
                level (str): Logging level for both outputs.
            """
            if MilesContext.Logger._configured:
                return MilesContext.Logger._logger

            loguru = MilesContext.Logger.try_import_loguru()
            logger = loguru.logger
            MilesContext.Logger._uuid = str(uuid.uuid4())
            MilesContext.Logger._configured = True

            log_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
            label_suffix = f"__{MilesContext.Logger._uuid}" if label is None else f"__{label}"
            log_file = log_dir / f"{timestamp}{label_suffix}.log"
            MilesContext.Logger._log_path = log_file

            # Remove any default handlers to avoid log duplication
            logger.remove()

            # Console handler
            if pretty_console:
                MilesContext.Logger._handler_ids.console = logger.add(sys.stderr, level=level, colorize=True, enqueue=True)

            # File handler
            MilesContext.Logger._handler_ids.file = logger.add(str(log_file), level=level, serialize=serialize, enqueue=True)

            logger.debug(f"[Logger Init] UUID={MilesContext.Logger._uuid} | Handlers=1, 2 → {log_file}")
            MilesContext.Logger._logger = logger
            return logger

        @staticmethod
        def get_loguru():
            """
            Get the initialized loguru logger instance. Raises error if not configured.
            """
            if not MilesContext.Logger._configured:
                raise RuntimeError("Logger has not been initialized. Call Logger.init_logger() first.")
            return MilesContext.Logger._logger

        @staticmethod
        def diagnostics():
            """
            Print current logger diagnostics including UUID and active handlers.
            """
            print("Logger Diagnostics:")
            print(f"  UUID:       {MilesContext.Logger._uuid}")
            print(f"  Configured: {MilesContext.Logger._configured}")
            print(f"  Log Path:   {MilesContext.Logger._log_path}")
            print(f"  Handler ID: console={MilesContext.Logger._handler_ids.console}, file={MilesContext.Logger._handler_ids.file}")

        @staticmethod
        def reset():
            """
            Reset logger state. Only use in test teardown.
            """
            if MilesContext.Logger._logger:
                MilesContext.Logger._logger.remove()
            MilesContext.Logger._configured = False
            MilesContext.Logger._uuid = None
            MilesContext.Logger._logger = None
            MilesContext.Logger._log_path = None
            MilesContext.Logger._handler_ids = SimpleNamespace(file=None, console=None)

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
                label: Optional[str] = None,
        ):
            def decorator(fn: Callable):
                if isinstance(fn, (staticmethod, classmethod)):
                    fn = fn.__func__
                uid = uuid.uuid4().hex[:8]
                name = label or fn.__name__

                @wraps(fn)
                def wrapper(*args, **kwargs):
                    # Ensure logger is initialized first
                    MilesContext.Logger.init_logger()
                    log = MilesContext.Logger.get_loguru()
                    log.debug(f"[{name}] 🎯 Entering decorator {uid}")

                    # Inject LOG + env into global namespace
                    fn.__globals__["LOG"] = log
                    for k, v in MilesContext.EnvLoader.load_env().items():
                        if k.isidentifier() and k.isupper():
                            fn.__globals__[k] = v

                    # ── Hijack only once ───────────────────────────────────────
                    is_log_parent = not hasattr(thread_local, "hijack_depth") or thread_local.hijack_depth == 0
                    if is_log_parent:
                        thread_local.hijack_depth = 1
                        thread_local.orig_print = builtins.print
                        thread_local.orig_echo = click.echo
                        builtins.print = lambda *a, **k: log.info(" ".join(map(str, a)))
                        click.echo = lambda *a, **k: log.info(" ".join(map(str, a)))
                    else:
                        thread_local.hijack_depth += 1

                    try:
                        # ── Load + apply env overrides ────────────────────────
                        if env:
                            log.debug(f"[{name}] Loading .env + config overrides")
                            MilesContext.EnvLoader.load_env()
                            try:
                                MilesContext.Config.apply_env(overwrite=True)
                            except Exception as e:
                                log.warning(f"[{name}] Failed to apply config overrides: {e}")

                        # ── Inject env vars into kwargs ───────────────────────
                        env_cache = MilesContext.EnvLoader._cache
                        sig = inspect.signature(fn)
                        accepted_keys = set(sig.parameters)
                        for k, v in env_cache.items():
                            if k in accepted_keys and k not in kwargs:
                                kwargs[k] = v

                        # ── Core logic ────────────────────────────────────────
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

                        if retry:
                            if fix:
                                if not callable(fix):
                                    raise TypeError(f"[{name}] fix must be callable, got {type(fix)}")
                                return StaticMethods.ErrorHandling.recall(core, fix=fix, label=name)
                            return StaticMethods.ErrorHandling.attempt(core, label=name)

                        if safe:
                            try:
                                return core()
                            except Exception as e:
                                log.warning(f"[{name}] Exception caught in safe mode: {e}")
                                return None

                        return core()

                    finally:
                        thread_local.hijack_depth -= 1
                        if thread_local.hijack_depth == 0:
                            builtins.print = thread_local.orig_print
                            click.echo = thread_local.orig_echo
                            del thread_local.hijack_depth
                            del thread_local.orig_print
                            del thread_local.orig_echo

                return wrapper

            return decorator

        # ──────────────────────────── Helper Methods ─────────────────────────────

        @staticmethod
        def _inject_globals(fn, log):
            fn.__globals__["LOG"] = log
            for k, v in MilesContext.EnvLoader.load_env().items():
                if k.isidentifier() and k.isupper():
                    fn.__globals__[k] = v

        @staticmethod
        def _inject_env_kwargs(fn, kwargs):
            sig = inspect.signature(fn)
            accepted = set(sig.parameters)
            env_cache = MilesContext.EnvLoader._cache
            for k, v in env_cache.items():
                if k in accepted and k not in kwargs:
                    kwargs[k] = v

        @staticmethod
        def _apply_env_overrides(log, name):
            log.debug(f"[{name}] Loading .env + config overrides")
            MilesContext.EnvLoader.load_env()
            try:
                MilesContext.Config.apply_env(overwrite=True)
            except Exception as e:
                if "ext" in str(e):
                    log.warning(f"[{name}] Did you mistakenly pass 'ext' to FileIO.write?")
                log.warning(f"[{name}] Failed to apply config overrides: {e}")

        @staticmethod
        def _hijack_stdout(log):
            thread_local.orig_print = builtins.print
            thread_local.orig_echo = click.echo
            builtins.print = lambda *a, **k: log.info(" ".join(map(str, a)))
            click.echo = lambda *a, **k: log.info(" ".join(map(str, a)))

        @staticmethod
        def _restore_stdout():
            builtins.print = thread_local.orig_print
            click.echo = thread_local.orig_echo

    @staticmethod
    def mileslib(fn: Optional[Callable] = None, **kwargs):
        """
        Flexible decorator shim that supports both:
        - @mileslib
        - @mileslib(...)
        """
        if fn is not None and callable(fn) and not kwargs:
            # Case: @mileslib
            return MilesContext.Decorator.mileslib()(fn)
        elif fn is None or callable(fn):
            # Case: @mileslib(...)
            return MilesContext.Decorator.mileslib(**kwargs)
        else:
            raise TypeError("Invalid usage of @mileslib")

mc = MilesContext
mileslib = mc.mileslib
ROOT = Path(mc.env.get("global_root"))
