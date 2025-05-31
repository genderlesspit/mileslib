import builtins
import contextvars
import shlex
import shutil
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from unittest import mock
from urllib.parse import urlparse
import os
import subprocess
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.keyvault.models import (
    VaultCreateOrUpdateParameters,
    AccessPolicyEntry,
    Permissions,
    Sku,
    SkuName,
    KeyPermissions,
    SecretPermissions,
    CertificatePermissions
)
from azure.core.exceptions import ResourceExistsError
import shutil
import subprocess
import platform
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
import psutil
import uvicorn
import yaml
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from click import Abort
from click.exceptions import Exit
from django.core.mail.message import sanitize_address
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
import ctypes

if TYPE_CHECKING:
    LOG: Any  # let IDEs think it's there

import os
import sys
import shlex
import subprocess
import platform
from shutil import which


import os
import sys
import platform
import shlex
import subprocess
from shutil import which

print("ENV['PATH']:\n", os.environ.get("PATH"))
print("\nshutil.which('az'):", shutil.which("az"))

try:
    subprocess.run(["az", "--version"], check=True)
except Exception as e:
    print("subprocess failed:", e)

import re


class Sanitization:
    """
    Utility class to sanitize names for different environments
    by removing or replacing invalid characters.
    """

    @staticmethod
    def purge(secret_key: str) -> str:
        """
        Purges a secret key by removing everything except alphanumeric characters (a-z, A-Z, 0-9),
        and converts all characters to lowercase.

        Args:
            secret_key (str): The secret name to be sanitized.

        Returns:
            str: The sanitized and lowercase secret name.
        """
        # Remove any character that is not alphanumeric and convert to lowercase
        sanitized_key = re.sub(r'[^a-zA-Z0-9]', '', secret_key).lower()
        return sanitized_key

    @staticmethod
    def sanitize_for_azure(secret_name: str) -> str:
        """
        Sanitizes a secret name to comply with Azure Key Vault naming restrictions.
        Replaces invalid characters with underscores or removes them.

        Azure Key Vault naming restrictions include:
        - No spaces
        - No special characters (e.g., `:`, `/`, `?`, `.`)

        Args:
            secret_name (str): The original secret name.

        Returns:
            str: The sanitized secret name.
        """
        # Define a pattern to match invalid characters
        # Azure Key Vault only supports alphanumeric characters, hyphens, and underscores.
        # We'll replace any invalid character with an underscore
        sanitized_name = re.sub(r'[^a-zA-Z0-9_-]', '_', secret_name)

        return sanitized_name

    @staticmethod
    def sanitize_for_other(secret_name: str) -> str:
        """
        Sanitizes a secret name for general usage or other systems' naming conventions.
        This can be extended to any other system's requirements.

        Args:
            secret_name (str): The original secret name.

        Returns:
            str: The sanitized secret name.
        """
        # You can add additional sanitization rules here for other systems
        sanitized_name = re.sub(r'[^a-zA-Z0-9_-]', '', secret_name)
        return sanitized_name


class Subprocess:
    class CMD:
        @staticmethod
        @staticmethod
        def run(
                cmd: str | list,
                *,
                shell=False,
                capture_output=True,
                check=True,
                text=True,
                env=None,
                force_global_shell=False
        ):
            """
            Runs a subprocess with optional global shell enforcement.

            Behavior:
            - If `cmd` is a string and shell=False, it's split safely.
            - On Windows, `.cmd` and `.bat` files are automatically wrapped with `cmd.exe /c`.
            - If `force_global_shell=True`, `cmd.exe /c` is prepended regardless.
            - Logs the final command to be run.
            """

            system_is_windows = platform.system() == "Windows"

            # Normalize string command input
            if isinstance(cmd, str) and not shell:
                cmd = shlex.split(cmd)

            # Auto-wrap .cmd/.bat on Windows if not already done
            if isinstance(cmd, list) and system_is_windows:
                first = cmd[0].lower()
                if first.endswith(".cmd") or first.endswith(".bat"):
                    cmd = ["cmd.exe", "/c"] + cmd

            # Explicit force_global_shell wrapper
            if force_global_shell and system_is_windows:
                cmd = ["cmd.exe", "/c"] + cmd
                shell = False  # Ensure shell=False with manual cmd.exe call

            print(f"[CMD] Running: {cmd}")
            return subprocess.run(
                cmd,
                shell=shell,
                capture_output=capture_output,
                check=check,
                text=text,
                env=env,
            )

        @staticmethod
        def system_python() -> str:
            """Return a path to the system Python executable."""
            if platform.system() == "Windows":
                try:
                    result = subprocess.run(["py", "-0p"], capture_output=True, text=True, check=True)
                    return result.stdout.strip().splitlines()[0]
                except Exception as e:
                    print(f"[CMD] Failed to resolve system Python via `py -0p`: {e}")
            return "python"  # fallback

        @staticmethod
        def pip_install(package: str | list, *, upgrade=False, global_scope=False):
            pkgs = [package] if isinstance(package, str) else package
            exe = Subprocess.CMD.system_python() if global_scope else sys.executable
            cmd = [exe, "-m", "pip", "install"]
            if upgrade:
                cmd.append("--upgrade")
            cmd.extend(pkgs)
            return Subprocess.CMD.run(cmd)

        @staticmethod
        def pipx_install_global(package: str):
            """Installs a package globally with pipx using system Python."""
            python = Subprocess.CMD.system_python()

            pipx_installed = subprocess.run(["pipx", "--version"], capture_output=True).returncode == 0
            if not pipx_installed:
                print("[Installer] pipx not found. Installing globally via system Python...")
                subprocess.run([python, "-m", "pip", "install", "--user", "pipx"], check=True)
                subprocess.run([python, "-m", "pipx", "ensurepath"], check=True)

            print(f"[Installer] Installing '{package}' globally with pipx...")
            return subprocess.run(["pipx", "install", package], check=True)

        @staticmethod
        def winget_install(command: list[str]):
            """
            Executes a winget command in a system shell with elevation.
            """
            if platform.system() != "Windows":
                raise RuntimeError("winget is only available on Windows.")

            full_cmd = " ".join(command)
            elevated = [
                "powershell", "-Command",
                f"Start-Process cmd -ArgumentList '/c {full_cmd}' -Verb runAs"
            ]
            print(f"[CMD] Elevating and running winget: {full_cmd}")
            subprocess.run(elevated, check=True)

        @staticmethod
        def powershell_install(script: str):
            return Subprocess.CMD.run(["powershell", "-Command", script], shell=True)

        @staticmethod
        def which(binary: str) -> str | None:
            return which(binary)

    class ExternalDependency:
        INSTALLERS = {
            "azure": {
                "check": "az",
                "winget": ["winget", "install", "--id", "Microsoft.AzureCLI", "-e", "--source", "winget"]
            },
            "rust": {
                "check": "rustc",
                "powershell": "iwr https://sh.rustup.rs -UseBasicParsing | iex",
            },
            "docker": {
                "check": "docker",
                "winget": ["winget", "install", "--id", "Docker.DockerDesktop", "-e", "--source", "winget"],
            },
        }

        @staticmethod
        def in_venv() -> bool:
            return hasattr(sys, "real_prefix") or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)

        @staticmethod
        def ensure(tool: str):
            if tool == "all":
                return print("All installed succesfully!")
            tool = tool.lower()
            if tool not in Subprocess.ExternalDependency.INSTALLERS:
                raise ValueError(f"[Installer] Unknown tool: {tool}")

            exe = Subprocess.ExternalDependency.INSTALLERS[tool]["check"]
            if Subprocess.CMD.which(exe):
                print(f"[Installer] ✅ {tool} already installed.")
                return

            inst = Subprocess.ExternalDependency.INSTALLERS[tool]
            try:
                if "pipx" in inst:
                    Subprocess.CMD.pipx_install_global(inst["pipx"])
                elif "winget" in inst:
                    Subprocess.CMD.winget_install(inst["winget"])
                elif "powershell" in inst:
                    Subprocess.CMD.powershell_install(inst["powershell"])
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"[Installer] Install failed for {tool}: {e}")

            Subprocess.ExternalDependency.post_install_check(tool)

        @staticmethod
        def ensure_all():
            for tool in Subprocess.ExternalDependency.INSTALLERS:
                Subprocess.ExternalDependency.ensure(tool)

        @staticmethod
        def post_install_check(tool: str):
            """
            Verifies whether the installed tool is available in PATH.
            - Checks `which()`.
            - Forces PATH refresh (Windows only).
            - Checks fallback install locations.
            - Prompts for IDE restart if running in a virtual environment.
            - Otherwise, force restarts PyCharm if it's running.
            """
            exe = Subprocess.ExternalDependency.INSTALLERS[tool]["check"]

            def found(msg=""):
                print(f"[Installer] ✅ {tool} is now available.{msg}")
                return

            def restart_pycharm_if_running():
                for proc in psutil.process_iter(["name", "exe"]):
                    name = proc.info.get("name", "").lower()
                    if "pycharm" in name:
                        try:
                            path = proc.info["exe"]
                            print(f"[Installer] 🔁 Restarting PyCharm: {path}")
                            proc.kill()
                            time.sleep(2)
                            subprocess.Popen([path])
                            return
                        except Exception as e:
                            print(f"[Installer] ⚠️ Failed to restart PyCharm: {e}")
                print(f"[Installer] ℹ️ PyCharm not detected — no restart needed.")

            def is_venv():
                return sys.prefix != getattr(sys, "base_prefix", sys.prefix)

            # Check PATH first
            if Subprocess.CMD.which(exe):
                return found()

            # Force a PATH refresh (Windows only)
            if platform.system() == "Windows":
                try:
                    refresh_path_cmd = [
                        "powershell", "-Command",
                        "[Environment]::SetEnvironmentVariable('Path', "
                        "[Environment]::GetEnvironmentVariable('Path','Machine') + ';' + "
                        "[Environment]::GetEnvironmentVariable('Path','User'), 'Process')"
                    ]
                    Subprocess.CMD.run(refresh_path_cmd, shell=True)
                    time.sleep(1)
                except Exception as e:
                    print(f"[Installer] ⚠️ Failed to force PATH refresh: {e}")

            # Recheck after refresh
            if Subprocess.CMD.which(exe):
                return found(" (after PATH refresh)")

            # Fallback path (Azure CLI)
            if tool == "azure":
                fallback = Path("C:/Program Files (x86)/Microsoft SDKs/Azure/CLI2/wbin/az.cmd")
                if fallback.exists():
                    print(f"[Installer] ✅ {tool} is installed at fallback location.")
                    print(f"🧠  You can manually run it via: {fallback}")
                    return

            # Final attempt: IDE warning or restart
            if is_venv():
                print(f"[Installer] ⚠️ {tool} may not be visible inside the virtual environment.")
                print("💡 Please close and reopen your IDE to reload PATH.")
            else:
                restart_pycharm_if_running()

            # Still not found
            raise RuntimeError(f"[Installer] ❌ {tool} still not found in PATH after install.")


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
        def recall(fn: Callable, fix: Union[Callable, List[Callable]]) -> Any:
            """
            Calls a zero-argument function with retry logic and one or more fix strategies.

            If `fn()` fails, will try one or more `fix()` strategies to recover and reattempt.

            Args:
                fn (Callable[[], Any]): Primary function to run.
                fix (Callable or list of Callable): Fix strategy or list of fallback functions.

            Returns:
                Any: Result of the successful call to `fn`.

            Raises:
                RuntimeError: If all fix attempts fail.
                TypeError: If non-callables are passed.
            """
            if not callable(fn):
                raise TypeError("[recall] First argument must be callable")

            # Try the main function first
            try:
                result = fn()
                print(f"[recall] Primary function succeeded")
                return result
            except Exception as e:
                print(f"[recall] Primary function failed: {e}")

            # Try fix(es)
            fixes = fix if isinstance(fix, list) else [fix]
            for i, fix_fn in enumerate(fixes):
                if not callable(fix_fn):
                    raise TypeError(f"[recall] Fix at index {i} is not callable: {fix_fn}")
                try:
                    print(f"[recall] Attempting fix #{i + 1}: {fix_fn.__name__}")
                    fix_fn()
                    print(f"[recall] Fix #{i + 1} succeeded. Retrying primary function...")
                    result = fn()
                    print(f"[recall] Retry succeeded after fix #{i + 1}")
                    return result
                except Exception as fix_err:
                    print(f"[recall] Fix #{i + 1} failed: {fix_err}")

            raise RuntimeError("[recall] All fix strategies failed. Aborting.")

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
        def check_types(arg: Any, expected: Union[Type, Tuple[Type, ...], list], label: str = "check_types") -> Any:
            """
            Verifies that the input or each item in a list matches any of the expected type(s).
            Raises TypeError if any do not match.

            Args:
                arg (Any): The argument or list of arguments to check.
                expected (Type, tuple, or list of types): Acceptable types (e.g., str, int).
                label (str): Label for clearer error messages.

            Returns:
                The original arg if valid.

            Raises:
                TypeError: If any input does not match the expected types.
            """

            # Normalize expected types to tuple
            if isinstance(expected, list):
                expected_types = tuple(expected)
            elif isinstance(expected, type):
                expected_types = (expected,)
            elif isinstance(expected, tuple):
                expected_types = expected
            else:
                raise TypeError(f"[{label}] Invalid 'expected' type: {type(expected)}")

            def _validate(x):
                if not isinstance(x, expected_types):
                    type_names = ", ".join(t.__name__ for t in expected_types)
                    raise TypeError(f"[{label}] Expected type(s): {type_names}; got {type(x).__name__}")

            if isinstance(arg, list):
                for i, item in enumerate(arg):
                    _validate(item)
            else:
                _validate(arg)

            return arg

    timer = ErrorHandling.timer
    attempt = ErrorHandling.attempt
    recall = ErrorHandling.recall
    check_input = ErrorHandling.check_types
    check_types = ErrorHandling.check_types
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
}

# ─── Default Global Config Values ───────────────────────────────
GLOBAL_CFG_DEFAULT = {
    "selected_project_name": None,
    "selected_project_path": None,
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
            """
            if not sm.check_types(path, expected=Path):
                raise FileNotFoundError

            file_ext = StaticMethods.FileIO.resolve_extension(path)

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

            try:
                if file_ext not in parsers:
                    raise TypeError(f"[Config.dump] Unsupported config format: {file_ext}")
                parsed_data = parsers[file_ext](path)
                if not isinstance(parsed_data, dict):
                    raise TypeError(f"[Config.dump] Parsed config is not a dict: {type(parsed_data)}")
                return parsed_data
            except Exception as e:
                raise RuntimeError(f"[Config.dump] Failed to parse config at {path}: {e}")

        @staticmethod
        def fetch(path: Path = GLOBAL_CFG_FILE) -> dict:
            """
            Ensures the config file exists, then loads and returns its parsed contents.

            Args:
                path (Path): Path to the config file.

            Returns:
                dict: Parsed configuration data.
            """
            def fallback():
                MilesContext.Config.build(path)
                return MilesContext.Config.dump(path)  # reload as dict

            loaded_cfg = sm.recall(
                lambda: MilesContext.Config.dump(path),
                lambda: fallback
            )
            return loaded_cfg

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
            print(f"[Config.get] Config successfully loaded: {data}")

            try:
                for key in keys:
                    data = data[key]
                return data
            except (KeyError, TypeError) as e:
                raise RuntimeError(f"[Config.get] Key path {keys} not found or invalid: {e}")

        @staticmethod
        def deep_merge(target: dict, updates: dict):
            for k, v in updates.items():
                if isinstance(v, dict) and isinstance(target.get(k), dict):
                    MilesContext.Config.deep_merge(target[k], v)
                else:
                    target[k] = v

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
            data = MilesContext.Config.fetch(path)

            if set:
                for k, v in set.items():
                    if isinstance(v, dict) and isinstance(data.get(k), dict):
                        MilesContext.Config.deep_merge(data[k], v)
                    else:
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
        Use @milescallback("/callback") to block function execution until a GET request is received.
        """

        _app = FastAPI()
        _lock = threading.Lock()
        _result = None
        _triggered = False
        _server_thread = None
        _callback_path = None
        _port = 8000

        @staticmethod
        def _reset():
            MilesContext.AsyncCallbacks._result = None
            MilesContext.AsyncCallbacks._triggered = False
            MilesContext.AsyncCallbacks._server_thread = None
            MilesContext.AsyncCallbacks._callback_path = None

        @staticmethod
        def _validate_path(path: str) -> str:
            if not path.startswith("/"):
                raise ValueError(f"[AsyncCallbacks] Invalid path '{path}': must start with '/'")
            return path

        @staticmethod
        def _start_server(log):
            try:
                log.debug(f"[AsyncCallbacks] Starting FastAPI server on 127.0.0.1:{MilesContext.AsyncCallbacks._port}")
                uvicorn.run(MilesContext.AsyncCallbacks._app, host="127.0.0.1", port=MilesContext.AsyncCallbacks._port, log_level="error")
            except Exception as e:
                log.exception(f"[AsyncCallbacks] Failed to start server: {e}")

        @staticmethod
        def async_callback(path: str = "/callback", timeout: float = 60):
            """
            Decorator that blocks the function until a GET request is received at `path`.
            Automatically spins up a temporary FastAPI server at http://localhost:8000.

            Args:
                path (str): Path to listen for the callback (e.g. "/callback").
                timeout (float): Seconds to wait before timing out.

            Returns:
                Decorator that passes callback query parameters to the wrapped function.
            """

            def decorator(fn: Callable[[dict], Any]):
                @wraps(fn)
                def wrapper(*args, **kwargs):
                    log = MilesContext.Logger.get_loguru()
                    validated_path = MilesContext.AsyncCallbacks._validate_path(path)

                    with MilesContext.AsyncCallbacks._lock:
                        if MilesContext.AsyncCallbacks._triggered:
                            log.warning("[AsyncCallbacks] Already triggered; reset required")
                            MilesContext.AsyncCallbacks._reset()

                        if MilesContext.AsyncCallbacks._server_thread is None:
                            log.debug(f"[AsyncCallbacks] Registering GET route at {validated_path}")

                            @MilesContext.AsyncCallbacks._app.get(validated_path)
                            async def _callback(req: Request):
                                MilesContext.AsyncCallbacks._result = dict(req.query_params)
                                MilesContext.AsyncCallbacks._triggered = True
                                log.info(f"[AsyncCallbacks] Callback received: {MilesContext.AsyncCallbacks._result}")
                                return JSONResponse({"status": "received"})

                            MilesContext.AsyncCallbacks._callback_path = validated_path
                            MilesContext.AsyncCallbacks._server_thread = threading.Thread(
                                target=MilesContext.AsyncCallbacks._start_server,
                                args=(log,),
                                daemon=True
                            )
                            MilesContext.AsyncCallbacks._server_thread.start()

                    log.info(f"[AsyncCallbacks] Waiting for callback on {validated_path}... (timeout={timeout}s)")
                    start = time.time()

                    while not MilesContext.AsyncCallbacks._triggered and (time.time() - start < timeout):
                        time.sleep(0.5)

                    if not MilesContext.AsyncCallbacks._triggered:
                        log.warning(f"[AsyncCallbacks] Timeout waiting for callback at {validated_path}")

                    result = MilesContext.AsyncCallbacks._result or {}
                    try:
                        return fn(result, *args, **kwargs)
                    finally:
                        MilesContext.AsyncCallbacks._reset()
                        log.debug("[AsyncCallbacks] Callback state reset")

                return wrapper

            return decorator

    @staticmethod
    def milescallback(path: str = "/callback", timeout: float = 60):
        """
        Shorthand for @MilesContext.AsyncCallbacks.async_callback.

        Example usage:
            @milescallback("/callback")
            def receive_callback(data):
                print("Received data:", data)

        Args:
            path (str): Path to listen on (must start with "/").
            timeout (float): How many seconds to wait before timeout.

        Returns:
            Decorator that blocks until the callback is received.
        """
        return MilesContext.AsyncCallbacks.async_callback(path=path, timeout=timeout)

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

                                # plain mode, no wrapper
                                return core_fn()
                        except Exception as e:
                            log.exception(f"[{name}] ❌ Uncaught exception: {e}")
                            raise RuntimeError(f"[{name}] ❌ Crashed with: {e}") from e

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
            """
            Injects logger, shared resources, and all uppercase env vars into fn.__globals__.

            Overwrites existing globals for dynamic reconfiguration.

            Only injects if:
            - The key is a valid Python identifier (k.isidentifier())
            - The key is ALL UPPERCASE
            """
            try:
                injectables = {
                    "log": log,
                    "requests_session": BackendMethods.Requests.session,
                    **{
                        k: v
                        for k, v in MilesContext.EnvLoader.load_env().items()
                        if k.isidentifier() and k.isupper()
                    }
                }

                for k, v in injectables.items():
                    old = fn.__globals__.get(k, "<unset>")
                    fn.__globals__[k] = v
                    log.debug(f"[{fn.__qualname__}] Overwrote global {k}: {old} -> {v}")
            except AttributeError:
                log.warning(f"[{fn.__qualname__}] No __globals__ found; skipping global injection")

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
milescallback = mc.milescallback
ROOT = Path(mc.env.get("global_root"))

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

        session = requests.Session()

        @staticmethod
        def _do_request(
                method: str,
                url: str,
                *,
                data=None,
                json=None,
                headers=None,
                timeout: float = 5.0,
                expect_json: bool = False
        ) -> requests.Response | dict | str | None:
            """
            Core request logic used by all HTTP wrappers.

            Args:
                method (str): HTTP method name, e.g. 'get', 'post'.
                url (str): Full URL to request.
                data/json (dict): Optional request payload.
                headers (dict): Optional headers.
                timeout (float): Request timeout in seconds.
                expect_json (bool): If True, return parsed JSON or raise.

            Returns:
                Response object or JSON dict or None
            """
            sm.try_import("requests")
            sm.check_types(method, str, "method")
            sm.check_types(url, str, "url")

            method = method.lower()
            req = getattr(BackendMethods.Requests.session, method)
            resp = req(url, data=data, json=json, headers=headers, timeout=timeout)
            resp.raise_for_status()

            if expect_json:
                return resp.json()

            return resp

        @staticmethod
        @mileslib(logged=False, safe=True)
        def http_get(
                url: str,
                headers: dict = None,
                retries: int = 3,
                timeout: float = 5.0,
                expect_json: bool = False
        ) -> requests.Response | dict | None:
            """
            HTTP GET with retries and optional JSON parsing.

            Args:
                url (str): URL to GET.
                headers (dict): Optional headers.
                retries (int): Retry attempts.
                timeout (float): Timeout in seconds.
                expect_json (bool): If True, return response.json().

            Returns:
                Response or parsed JSON or None.
            """
            return sm.attempt(
                lambda: BackendMethods.Requests._do_request(
                    "get",
                    url,
                    headers=headers,
                    timeout=timeout,
                    expect_json=expect_json,
                ),
                retries=retries
            )

        @staticmethod
        @mileslib(logged=False, safe=True)
        def http_post(
                url: str,
                data: dict,
                headers: dict = None,
                retries: int = 3,
                timeout: float = 5.0,
                expect_json: bool = False
        ) -> requests.Response | dict | None:
            """
            HTTP POST with retries and JSON payload.

            Args:
                url (str): URL to POST to.
                data (dict): JSON payload.
                headers (dict): Optional headers.
                retries (int): Retry attempts.
                timeout (float): Timeout in seconds.
                expect_json (bool): If True, return response.json().

            Returns:
                Response or parsed JSON or None.
            """
            sm.check_types(data, dict, "data")
            return sm.attempt(
                lambda: BackendMethods.Requests._do_request(
                    "post",
                    url,
                    json=data,
                    headers=headers,
                    timeout=timeout,
                    expect_json=expect_json,
                ),
                retries=retries
            )

        @staticmethod
        @mileslib(logged=False, safe=True)
        def ensure_endpoint(
                url: str,
                timeout: float = 3.0,
                expect_json: bool = False,
                expect_keys: list[str] = None,
                status_ok: range = range(200, 400),
        ) -> bool:
            """
            Check if an HTTP endpoint is up and optionally validate its response content.

            Args:
                url (str): URL to check.
                timeout (float): Timeout in seconds.
                expect_json (bool): If True, requires response to be JSON-decodable.
                expect_keys (list[str], optional): List of keys that must exist in JSON payload.
                status_ok (range): Acceptable status code range.

            Returns:
                bool: True if endpoint is reachable and meets criteria, False otherwise.
            """
            try:
                resp = BackendMethods.Requests._do_request("get", url, timeout=timeout)

                if hasattr(resp, "status_code") and resp.status_code not in status_ok:
                    print(f"[ensure_endpoint] Status code {resp.status_code} not in {list(status_ok)}")
                    return False

                if expect_json:
                    try:
                        payload = resp.json() if hasattr(resp, "json") else resp
                    except Exception:
                        print(f"[ensure_endpoint] Response is not valid JSON from {url}")
                        return False

                    if expect_keys:
                        missing = [k for k in expect_keys if k not in payload]
                        if missing:
                            print(f"[ensure_endpoint] Missing expected keys {missing} in response from {url}")
                            return False

                return True

            except Exception as e:
                print(f"[ensure_endpoint] Request to {url} failed: {e}")
                return False

    reqs = Requests
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


    class TemplateManager:
        _env = None
        _template_dir = GLOBAL_TEMPLATES_DIR or mc.cfg_get("template_directory")

        @staticmethod
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

    class ProjectUtils:
        """
        Utilities for managing and validating selected MilesLib project context.
        """

        @staticmethod
        def select_project(name: str, path: Path) -> Path:
            """
            Sets the selected MilesLib project by name or path into the global environment config.

            Args:
                name (str): The project name (directory name).
                path (Path): The full path to the project directory.

            Returns:
                Path: The resolved project path.

            Raises:
                TypeError: If name or path are not strings after normalization.
            """
            ensured_path = sm.validate_directory(path).resolve()
            str_path = str(ensured_path)
            args = [name, str_path]
            sm.check_types(args, str)  # Defensive: ensure all inputs are strings

            mc.env.write("selected_project_name", str_path, replace_existing=True)
            mc.env.write("selected_project_path", str_path, replace_existing=True)
            print(f"[select_project] Active project path set: {str_path}")
            return ensured_path

        @staticmethod
        def discover_projects(root: Path = ROOT) -> list[tuple[str, Path]]:
            """
            Scans root for valid MilesLib projects with config files.

            Returns:
                List of tuples: (project_name, project_path)
            """
            found = []
            for sub in root.iterdir():
                if not sub.is_dir() or sub.name.startswith("__") or "pycache" in sub.name.lower():
                    continue
                cfg = sub / f"mileslib_{sub.name}_settings.toml"
                if cfg.exists():
                    found.append((sub.name, sub.resolve()))
            return found

        @staticmethod
        def db_name(project: str) -> str:
            """
            Resolves and returns the database name for the project.
            If it does not exist, creates a default database name.

            Args:
                project (str): Project name

            Returns:
                str: Resolved or generated database name
            """
            db_name = mc.env.get(f"{project}.DB_NAME", required=False) or f"{project.lower()}-pg"
            mc.env.write(f"{project}.DB_NAME", db_name, replace_existing=True)
            return db_name

    class AzureTenant:
        """
        Manages Azure Tenant ID initialization, validation, and retrieval.

        Uses project-scoped keys: <project>.AZURE_TENANT_ID
        """

        @staticmethod
        def init(project: str) -> str:
            """
            Prompts the user for a valid Azure Tenant ID, validates, and stores it.

            Args:
                project (str, optional): Project name for scoping. Defaults to selected project.

            Returns:
                str: Validated and stored tenant ID.
            """
            key = f"{project}.AZURE_TENANT_ID"

            print(f"[AzureTenant] No tenant ID found for project: {project}")
            bm.AzureTenant.help()

            time.sleep(1)
            tenant_id = input("Enter your Azure Tenant ID: ").strip()
            bm.AzureTenant.validate(tenant_id)

            cfg_data = {
                "aad": {
                    "AZURE_TENANT_ID": f"{tenant_id}"
                }
            }
            cfg_root = mc.env.get(f"{project}.config_dir")
            mc.env.write(key, tenant_id, replace_existing=True)
            mc.cfg_write(project_root, set=cfg_data)
            print(f"[AzureTenant] Tenant ID set for project '{project}'")
            return tenant_id

        @staticmethod
        def get(project: str) -> str:
            """
            Retrieves the tenant ID for a project, prompting if missing.

            Args:
                project (str, optional): Project scope for env key. Defaults to selected project.

            Returns:
                str: Validated tenant ID.
            """
            key = f"{project}.AZURE_TENANT_ID"

            tenant_id = mc.env.get(key, required=False)
            if not tenant_id:
                return bm.AzureTenant.init(project)

            bm.AzureTenant.validate(tenant_id)
            return tenant_id

        @staticmethod
        def validate(tenant_id: str) -> bool:
            """
            Validates the given tenant ID by checking OpenID metadata.

            Args:
                tenant_id (str): The Azure AD tenant ID to validate.

            Returns:
                bool: True if valid, otherwise raises an error.
            """
            url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
            resp = bm.Requests.http_get(url, expect_json=True)
            if not isinstance(resp, dict) or tenant_id not in resp.get("issuer", ""):
                raise RuntimeError(f"[AzureTenant] Invalid tenant_id: {tenant_id}")
            return True

        @staticmethod
        def help():
            """
            Prints human instructions for locating your Azure Tenant ID.

            Excludes CLI methods that require a tenant ID.
            """
            print("[🔧 How to Find Your Azure Tenant ID]")
            print("─────────────────────────────────────")
            print("📍 Azure Portal (recommended):")
            print("  1. Go to: https://portal.azure.com/")
            print("  2. Select 'Azure Active Directory' from the sidebar.")
            print("  3. Your Tenant ID is listed on the Overview page.")
            print("🧠 Tip: It looks like a UUID (e.g. 72f988bf-86f1-41af-91ab-2d7cd011db47).")
            print("─────────────────────────────────────")

    class AzureSubscription:
        """
        Handles Azure Subscription ID selection, validation, and caching.

        Uses project-scoped key: <project>.AZURE_SUBSCRIPTION_ID
        """

        @staticmethod
        def init(project: str) -> str:
            """
            Prompts the user to choose a subscription if multiple exist,
            then stores and validates the selected subscription ID.

            Args:
                project (str): Project scope.

            Returns:
                str: Validated subscription ID.
            """
            print(f"[AzureSubscription] Fetching available subscriptions...")
            subs = bm.AzureSubscription._get_all()

            if not subs:
                raise RuntimeError("[AzureSubscription] No subscriptions found. Are you logged in to Azure?")

            if len(subs) == 1:
                sub = subs[0]
                print(f"[AzureSubscription] One subscription found: {sub['name']} ({sub['id']})")
            else:
                print("\n🔢 Choose a subscription:")
                for i, s in enumerate(subs, 1):
                    print(f" {i}. {s['name']} ({s['id']})")
                print()

                while True:
                    try:
                        idx = int(input(f"Enter number (1–{len(subs)}): ").strip()) - 1
                        if 0 <= idx < len(subs):
                            sub = subs[idx]
                            break
                    except Exception:
                        pass
                    print("❌ Invalid input. Try again.")

            sub_id = sub["id"]
            key = f"{project}.AZURE_SUBSCRIPTION_ID"
            mc.env.write(key, sub_id, replace_existing=True)

            cfg_root = mc.env.get(f"{project}.config_dir", required=True)
            mc.cfg_write(cfg_root, set={
                "aad": {
                    "AZURE_SUBSCRIPTION_ID": sub_id
                }
            })

            print(f"[AzureSubscription] Subscription set: {sub['name']} ({sub_id})")
            return sub_id

        @staticmethod
        def get(project: str) -> str:
            """
            Retrieves the project’s subscription ID or triggers selection.

            Args:
                project (str): Project name.

            Returns:
                str: Subscription ID
            """
            key = f"{project}.AZURE_SUBSCRIPTION_ID"
            sub_id = mc.env.get(key, required=False)
            if not sub_id:
                return bm.AzureSubscription.init(project)

            bm.AzureSubscription.validate(sub_id)
            return sub_id

        @staticmethod
        def validate(sub_id: str) -> bool:
            """
            Verifies the subscription ID exists in the current Azure context.

            Args:
                sub_id (str): Azure subscription ID

            Returns:
                bool: True if valid; raises if invalid
            """
            subs = bm.AzureSubscription._get_all()
            valid_ids = [s["id"] for s in subs]
            if sub_id not in valid_ids:
                raise ValueError(f"[AzureSubscription] Subscription ID not recognized: {sub_id}")
            return True

        @staticmethod
        def _get_all() -> list[dict]:
            """
            Returns a list of all available Azure subscriptions.

            Returns:
                list of dicts with 'id' and 'name'
            """
            raw = Subprocess.CMD.run(
                ["az", "account", "list", "--output", "json"],
                capture_output=True, text=True, check=True, force_global_shell=True
            ).stdout
            import json
            return json.loads(raw)

        @staticmethod
        def help():
            """
            Prints CLI guidance on managing Azure subscriptions.
            """
            print("\n[🔧 Azure Subscription Help]")
            print("────────────────────────────")
            print("1. Sign in with: `az login`")
            print("2. See subscriptions: `az account list --output table`")
            print("3. Set a default: `az account set --subscription <id>`")
            print("────────────────────────────\n")

    class AzureUser:
        """
        Handles interactive login to Azure CLI, caches the result, and validates
        the authenticated account against project-scoped tenant and subscription.

        Ensures:
          - Clean login (once per session)
          - Valid tenant ID and subscription ID
        """

        _cached_user = None

        @staticmethod
        def get(project: str) -> dict:
            """
            Returns the current user context, logging in if not already cached.

            Args:
                project (str): Project name

            Returns:
                dict: Validated CLI user context
            """
            if bm.AzureUser._cached_user:
                return bm.AzureUser._cached_user

            try:
                print("[AzureUser] Attempting to reuse existing Azure CLI session...")
                context = bm.AzureUser._validate_context(project)
            except Exception as e:
                print(f"[AzureUser] Existing session invalid or missing. Reason: {e}")
                context = bm.AzureUser.login(project)

            bm.AzureUser._cached_user = context
            print(f"User context successfully retrieved!: {context}")
            return context

        @staticmethod
        def login(project: str) -> dict:
            """
            Clears token cache, prompts interactive login, and validates context.

            Args:
                project (str): Project name

            Returns:
                dict: Validated user metadata
            """
            print("[AzureUser] 🔐 Logging in via Azure CLI...")
            tenant_id = bm.AzureTenant.get(project)

            # Add the tenant ID to the az login command
            Subprocess.CMD.run(
                ["az", "login", "--tenant", tenant_id, "--use-device-code"],
                capture_output=False,
                check=True,
                force_global_shell=True
            )

            context = bm.AzureUser._validate_context(project)
            bm.AzureUser._cached_user = context
            return context

        @staticmethod
        def _validate_context(project: str) -> dict:
            """
            Validates current CLI user against tenant and subscription.

            Args:
                project (str): Project scope

            Returns:
                dict: Validated account context
            """
            tenant_id = bm.AzureTenant.get(project)
            subscription_id = bm.AzureSubscription.get(project)

            result = Subprocess.CMD.run(
                ["az", "account", "show", "--output", "json"],
                capture_output=True, text=True, check=True, force_global_shell=True
            ).stdout

            import json
            user = json.loads(result)
            actual_tenant = user.get("tenantId")
            actual_sub = user.get("id")

            if actual_tenant != tenant_id:
                raise RuntimeError(f"[AzureUser] ❌ Tenant mismatch: CLI={actual_tenant} vs Config={tenant_id}")
            if actual_sub != subscription_id:
                raise RuntimeError(f"[AzureUser] ❌ Subscription mismatch: CLI={actual_sub} vs Config={subscription_id}")

            name = user.get("user", {}).get("name", "Unknown")
            print(f"[AzureUser] ✅ Logged in as: {name} ({user.get('userType')})")

            return {
                "tenant_id": actual_tenant,
                "subscription_id": actual_sub,
                "user": user.get("user", {}),
                "raw": user
            }

        @staticmethod
        def help():
            """
            CLI guidance for Azure login and account troubleshooting.
            """
            print("\n[🧠 Azure Login Help]")
            print("──────────────────────────────")
            print("1. `az logout && az account clear` — force sign-out")
            print("2. `az login` — sign in again")
            print("3. `az account show` — inspect current identity")
            print("──────────────────────────────\n")

    class AzureClient:
        """
        Manages Azure App Registrations: either retrieves an existing app or creates a new one.
        """

        @staticmethod
        def get_app(project: str) -> dict:
            """
            Retrieves an existing app registration for the specified project or creates a new one if not found.

            Args:
                project (str): Project name, used for scoping.

            Returns:
                dict: Contains app details, including client_id and appId.
            """
            print(f"[AzureClient] Checking if app registration exists for project '{project}'...")

            # Step 1: Check if the app registration exists
            app = bm.AzureClient._find_existing_app(project)

            # Step 2: If app doesn't exist, create it
            if not app:
                print(f"[AzureClient] App registration not found for project '{project}'. Creating a new one...")
                app = bm.AzureClient.create_app(project)

            return app

        @staticmethod
        def _find_existing_app(project: str) -> dict:
            """
            Checks if an app registration already exists for the given project.

            Args:
                project (str): Project name to check for app registration.

            Returns:
                dict: App registration details if found, otherwise None.
            """
            try:
                # Correct query to get appId and displayName
                result = Subprocess.CMD.run(
                    ["az", "ad", "app", "list", "--query", "[].{appId: appId, displayName: displayName}", "--output",
                     "json"],
                    capture_output=True, text=True, check=True
                )
                apps = json.loads(result.stdout)

                # Loop through the list of apps to check for an app with a matching display name or appId
                for app in apps:
                    if project.lower() in app['displayName'].lower():  # Match the project name
                        print(f"[AzureClient] Found existing app: {app['displayName']} ({app['appId']})")
                        return app

                return None
            except subprocess.CalledProcessError as e:
                print(f"[AzureClient] Error while checking for existing app: {e}")
                print(f"stdout: {e.stdout}")
                print(f"stderr: {e.stderr}")
                return None

        @staticmethod
        def create_app(project: str) -> dict:
            """
            Creates a new Azure AD app registration for the specified project.

            Args:
                project (str): Project name used for app registration display name.

            Returns:
                dict: Newly created app details, including client_id and appId.
            """
            print(f"[AzureClient] Creating new app registration for project '{project}'...")

            try:
                result = Subprocess.CMD.run(
                    ["az", "ad", "app", "create", "--display-name", project, "--query", "appId,displayName,appId",
                     "--output", "json"],
                    capture_output=True, text=True, check=True
                )
                new_app = json.loads(result.stdout)
                print(f"[AzureClient] Created new app: {new_app['displayName']} ({new_app['appId']})")
                return new_app
            except subprocess.CalledProcessError as e:
                print(f"[AzureClient] Error creating app registration: {e}")
                print(f"stdout: {e.stdout}")
                print(f"stderr: {e.stderr}")
                raise

    class AzureResourceGroup:
        """
        Handles discovery or creation of a resource group using Azure CLI or fallback logic.

        Priority:
        - EnvLoader: {project}.RESOURCE_GROUP
        - az group list → user selection
        - fallback default: <project>-rg
        """

        @staticmethod
        def get(project: str) -> str:
            """
            Resolves the resource group for the given project.

            Args:
                project (str): Project name

            Returns:
                str: Validated or selected resource group name
            """
            key = f"{project}.RESOURCE_GROUP"
            rg = mc.env.get(key, required=False)
            if rg:
                return rg

            print(f"[AzureResourceGroup] Resolving resource group for project: {project}")

            try:
                sub_id = bm.AzureIDs.subscription_id(project)
                result = Subprocess.CMD.run([
                    "az", "group", "list",
                    "--subscription", sub_id,
                    "--query", "[].name",
                    "--output", "tsv"
                ], capture_output=True, text=True, force_global_shell=True)

                groups = result.stdout.strip().splitlines()
                if not groups:
                    raise RuntimeError("[AzureResourceGroup] No resource groups found in this subscription.")

                print(f"[AzureResourceGroup] Select a resource group for project '{project}':")
                for i, g in enumerate(groups, start=1):
                    print(f"  {i}. {g}")

                idx = input(f"Enter number [1-{len(groups)}] (or press Enter to use default '{project}-rg'): ").strip()
                if idx.isdigit() and 1 <= int(idx) <= len(groups):
                    selected = groups[int(idx) - 1]
                    mc.env.write(key, selected, replace_existing=True)
                    print(f"[AzureResourceGroup] Selected: {selected}")
                    return selected

            except Exception as e:
                print(f"[AzureResourceGroup] CLI discovery failed: {e}")

            # Fallback
            default = f"{project}-rg"
            print(f"[AzureResourceGroup] Using fallback default: {default}")
            mc.env.write(key, default, replace_existing=True)
            return default

    class AzureKeyVault:
        """
        Resolves and verifies Key Vault URI for a project.

        Used by AzureIDs to populate KEY_VAULT_URL.
        """

        @staticmethod
        def get_url(project: str) -> str:
            """
            Returns a Key Vault URI for the given project.

            Tries:
            1. {project}.VAULT_NAME + az show
            2. bm.VaultSetup.ensure_vault_ready(project)

            Args:
                project (str): Project name

            Returns:
                str: Vault URI
            """
            vault_name = mc.env.get(f"{project}.VAULT_NAME", required=False)
            resource_group = bm.AzureIDs.resource_group(project)

            try:
                if vault_name:
                    result = Subprocess.CMD.run([
                        "az", "keyvault", "show",
                        "--name", vault_name,
                        "--resource-group", resource_group,
                        "--query", "properties.vaultUri",
                        "--output", "tsv"
                    ], capture_output=True, text=True, check=True, force_global_shell=True)
                    uri = result.stdout.strip()
                    if uri:
                        print(f"[AzureKeyVault] ✅ Resolved URI for vault '{vault_name}': {uri}")
                        return uri
            except Exception as e:
                print(f"[AzureKeyVault] Could not resolve vault URI via CLI: {e}")

            # Fallback: trigger vault creation
            LOG.info(f"[AzureKeyVault] Triggering vault setup fallback...")
            return bm.VaultSetup.ensure_vault_ready(project)

    class AzureIDs:
        """
        Resolves and validates Azure identity values required for authentication,
        authorization, and resource provisioning.

        Leverages composed classes:
          - AzureTenant
          - AzureSubscription
          - AzureClient
          - AzureAppRegister
          - AzureUser

        Uses project-scoped keys like <project>.AZURE_TENANT_ID
        """
        _cached_user = None

        REQUIRED_KEYS = {
            "AZURE_TENANT_ID": "Tenant ID",
            "AZURE_CLIENT_ID": "Client ID",
            "AZURE_CLIENT_SECRET": "Client Secret",
            "AZURE_SUBSCRIPTION_ID": "Subscription ID",
            "KEY_VAULT_URL": "Key Vault URL",
            "RESOURCE_GROUP": "Azure Resource Group",
            "AZURE_REGION": "Azure Region",
            "DB_NAME": "Database Name"
        }

        @staticmethod
        def get(key: str, project: str, required: bool = True) -> str:
            """
            Resolves a specific identity value from the configured project context.

            Args:
                key (str): Identity key name
                project (str): Project name
                required (bool): Raise error if not found

            Returns:
                str: Resolved identity value
            """
            #Ensure valid user ...
            try:
                user = bm.AzureIDs._cached_user
                if not user:
                    user = bm.AzureUser.get(project)

                if key == "AZURE_TENANT_ID":
                    return bm.AzureTenant.get(project)

                elif key == "AZURE_SUBSCRIPTION_ID":
                    return bm.AzureSubscription.get(project)

                elif key == "AZURE_CLIENT_ID":
                    return bm.AzureClient.get_app(project)["client_id"]

                elif key == "AZURE_CLIENT_SECRET":
                    return bm.AzureClient.setup(project)["client_secret"]

                elif key == "KEY_VAULT_URL":
                    return bm.AzureKeyVault.get_url(project)

                elif key == "RESOURCE_GROUP":
                    return bm.AzureResourceGroup.get(project)

                elif key == "AZURE_REGION":
                    return bm.AzureIDs._resolve_region(project)

                elif key == "DB_NAME":
                    return bm.ProjectUtils.db_name(project)

            except Exception as resolver_error:
                fallback_key = f"{project}.{key}"
                val = mc.env.get(fallback_key, required=False)
                if val:
                    return val
                if required:
                    raise RuntimeError(f"[AzureIDs] ❌ Failed to resolve {key}:\n{resolver_error}")
                return None

        @staticmethod
        def _resolve_region(project: str) -> str:
            """
            Attempts to resolve the Azure region via ENV or from the resource group's metadata.
            """
            env_key = f"{project}.AZURE_REGION"
            region = mc.env.get(env_key, required=False)
            if region:
                return region

            resource_group = bm.AzureIDs.resource_group(project)
            try:
                result = Subprocess.CMD.run(
                    [
                        "az", "group", "show",
                        "--name", resource_group,
                        "--query", "location",
                        "--output", "tsv"
                    ],
                    capture_output=True,
                    text=True,
                    force_global_shell=True
                )
                return result.stdout.strip()
            except Exception as e:
                raise RuntimeError(f"[AzureIDs] ❌ Could not resolve region from resource group '{resource_group}': {e}")

        @staticmethod
        def validate_all(project: str) -> dict:
            """
            Ensures all required identity values are resolvable.

            Args:
                project (str): Project name

            Returns:
                dict: All resolved identity values
            """
            for key in bm.AzureIDs.REQUIRED_KEYS:
                print(f"Attempting to validate {project}.{key}...")
                bm.AzureIDs.get(key, project=project, required=True)

        class AzureIDs:

            @staticmethod
            def tenant_id(project: str) -> str:
                """Get the AZURE_TENANT_ID."""
                tenant_id = mc.env.get("AZURE_TENANT_ID", None)
                if tenant_id is None:
                    tenant_id = bm.AzureIDs.get("AZURE_TENANT_ID", project)
                    mc.env.write("AZURE_TENANT_ID", tenant_id, replace_existing=True)
                return tenant_id

            @staticmethod
            def subscription_id(project: str) -> str:
                """Get the AZURE_SUBSCRIPTION_ID."""
                subscription_id = mc.env.get("AZURE_SUBSCRIPTION_ID", None)
                if subscription_id is None:
                    subscription_id = bm.AzureIDs.get("AZURE_SUBSCRIPTION_ID", project)
                    mc.env.write("AZURE_SUBSCRIPTION_ID", subscription_id, replace_existing=True)
                return subscription_id

            @staticmethod
            def client_id(project: str) -> str:
                """Get the AZURE_CLIENT_ID."""
                client_id = mc.env.get("AZURE_CLIENT_ID", None)
                if client_id is None:
                    client_id = bm.AzureIDs.get("AZURE_CLIENT_ID", project)
                    mc.env.write("AZURE_CLIENT_ID", client_id, replace_existing=True)
                return client_id

            @staticmethod
            def client_secret(project: str) -> str:
                """Get the AZURE_CLIENT_SECRET."""
                client_secret = mc.env.get("AZURE_CLIENT_SECRET", None)
                if client_secret is None:
                    client_secret = bm.AzureIDs.get("AZURE_CLIENT_SECRET", project)
                    mc.env.write("AZURE_CLIENT_SECRET", client_secret, replace_existing=True)
                return client_secret

            @staticmethod
            def key_vault_url(project: str) -> str:
                """Get the KEY_VAULT_URL."""
                key_vault_url = mc.env.get("KEY_VAULT_URL", None)
                if key_vault_url is None:
                    key_vault_url = bm.AzureIDs.get("KEY_VAULT_URL", project)
                    mc.env.write("KEY_VAULT_URL", key_vault_url, replace_existing=True)
                return key_vault_url

            @staticmethod
            def resource_group(project: str) -> str:
                """Get the RESOURCE_GROUP."""
                resource_group = mc.env.get("RESOURCE_GROUP", None)
                if resource_group is None:
                    resource_group = bm.AzureIDs.get("RESOURCE_GROUP", project)
                    mc.env.write("RESOURCE_GROUP", resource_group, replace_existing=True)
                return resource_group

            @staticmethod
            def region(project: str) -> str:
                """Get the AZURE_REGION."""
                region = mc.env.get("AZURE_REGION", None)
                if region is None:
                    region = bm.AzureIDs.get("AZURE_REGION", project)
                    mc.env.write("AZURE_REGION", region, replace_existing=True)
                return region

            @staticmethod
            def db_name(project: str) -> str:
                """Get the DB_NAME."""
                db_name = mc.env.get("DB_NAME", None)
                if db_name is None:
                    db_name = bm.AzureIDs.get("DB_NAME", project)
                    mc.env.write("DB_NAME", db_name, replace_existing=True)
                return db_name

    class VaultSetup:
        """
        Handles creation, validation, and retrieval of Azure Key Vaults for a given project context.

        Resolves dependencies via:
        - AzureIDs (tenant, sub, client, secret, resource group, vault name)
        - Secrets (for post-creation vault session)
        """

        @staticmethod
        def ensure_vault_ready(project: str = None) -> str:
            """
            Main entrypoint. Ensures Key Vault exists and is accessible.

            Returns:
                str: Vault URI
            """
            project = project or mc.env.get("selected_project_name")
            subscription_id = bm.AzureIDs.subscription_id(project)
            region = mc.env.get(f"{project}.AZURE_REGION", required=False) or "eastus"

            bm.VaultSetup.list_existing_vaults(subscription_id, region)

            try:
                vault = bm.VaultSetup.get_vault(project)
                print(f"[VaultSetup] ✅ Vault exists: {vault['name']} ({vault['uri']})")
            except Exception as e:
                print(f"[VaultSetup] ⚠️ Vault not found. Attempting to create it: {e}")
                vault = bm.VaultSetup.create_vault(project)

            uri = vault["uri"]

            if not Secrets.load_vault(project):
                raise RuntimeError("[VaultSetup] ❌ Failed to initialize Secrets client after vault creation.")

            return uri

        @staticmethod
        def list_existing_vaults(subscription_id: str, region: str = None) -> list:
            """
            Lists Key Vaults for the subscription (optionally filtered by region).
            """
            cmd = ["az", "keyvault", "list", "--subscription", subscription_id, "--output", "json"]
            result = Subprocess.CMD.run(cmd, capture_output=True, text=True, force_global_shell=True)
            import json
            vaults = json.loads(result.stdout)

            if region:
                vaults = [v for v in vaults if v.get("location", "").lower() == region.lower()]

            print(f"[VaultSetup] 🔍 Found {len(vaults)} vault(s){f' in region={region}' if region else ''}")
            for v in vaults:
                print(f"  - {v['name']} ({v['location']})")

            return vaults

        @staticmethod
        def ensure_keyvault_provider_registered(subscription_id: str):
            """
            Ensures the Microsoft.KeyVault provider is registered for the subscription.
            """
            result = Subprocess.CMD.run(
                ["az", "provider", "show", "--namespace", "Microsoft.KeyVault", "--query", "registrationState",
                 "--output", "tsv"],
                capture_output=True, text=True, force_global_shell=True
            )
            if result.stdout.strip() != "Registered":
                print("[VaultSetup] 🔧 Registering Microsoft.KeyVault provider...")
                Subprocess.CMD.run(
                    ["az", "provider", "register", "--namespace", "Microsoft.KeyVault"],
                    capture_output=True, text=True, force_global_shell=True
                )
                print("[VaultSetup] ⏳ Waiting for registration...")
                import time
                while True:
                    check = Subprocess.CMD.run(
                        ["az", "provider", "show", "--namespace", "Microsoft.KeyVault", "--query", "registrationState",
                         "--output", "tsv"],
                        capture_output=True, text=True, force_global_shell=True
                    )
                    if check.stdout.strip() == "Registered":
                        break
                    time.sleep(2)
                print("[VaultSetup] ✅ Provider registered.")

        @staticmethod
        def create_vault(project: str) -> dict:
            """
            Creates a new Key Vault.

            Returns:
                dict: { name, uri }
            """
            project = project or mc.env.get("selected_project_name")

            subscription_id = bm.AzureIDs.subscription_id(project)
            bm.VaultSetup.ensure_keyvault_provider_registered(subscription_id)

            vault_name = mc.env.get(f"{project}.VAULT_NAME", required=False) or f"{project.lower()}-vault"
            location = mc.env.get(f"{project}.AZURE_REGION", required=False) or "eastus"
            resource_group = bm.AzureIDs.resource_group(project)

            mc.env.write(f"{project}.VAULT_NAME", vault_name, replace_existing=True)

            print(f"[VaultSetup] 🚀 Creating Key Vault: {vault_name} in {resource_group} ({location})")

            Subprocess.CMD.run([
                "az", "keyvault", "create",
                "--name", vault_name,
                "--location", location,
                "--resource-group", resource_group,
                "--enable-rbac-authorization", "true"
            ], capture_output=True, text=True, force_global_shell=True)

            result = Subprocess.CMD.run([
                "az", "keyvault", "show",
                "--name", vault_name,
                "--resource-group", resource_group,
                "--query", "properties.vaultUri", "--output", "tsv"
            ], capture_output=True, text=True, force_global_shell=True)

            uri = result.stdout.strip()
            print(f"[VaultSetup] ✅ Vault created: {vault_name} ({uri})")

            return {"name": vault_name, "uri": uri}

        @staticmethod
        def get_vault(project: str) -> dict:
            """
            Uses Azure SDK to fetch vault metadata.

            Returns:
                dict: Vault metadata
            """
            from azure.mgmt.keyvault import KeyVaultManagementClient
            from azure.identity import DefaultAzureCredential

            project = project or mc.env.get("selected_project_name")
            subscription_id = bm.AzureIDs.subscription_id(project)
            vault_name = mc.env.get(f"{project}.VAULT_NAME", required=True)
            resource_group = bm.AzureIDs.resource_group(project)

            try:
                client = KeyVaultManagementClient(DefaultAzureCredential(), subscription_id)
                vault = client.vaults.get(resource_group_name=resource_group, vault_name=vault_name)

                return {
                    "name": vault.name,
                    "location": vault.location,
                    "id": vault.id,
                    "uri": vault.properties.vault_uri,
                    "policies": [p.object_id for p in vault.properties.access_policies],
                    "enabled_for_template_deployment": vault.properties.enabled_for_template_deployment,
                }
            except Exception as e:
                raise RuntimeError(f"[VaultSetup] ❌ Failed to retrieve vault '{vault_name}': {e}")

        @staticmethod
        def get_url(project: str) -> str | None:
            """
            Returns Key Vault URI if it exists; returns None if not found.
            Never creates or modifies vault.
            """
            try:
                vault = bm.VaultSetup.get_vault(project)
                return vault["uri"]
            except Exception:
                return None

        @staticmethod
        def get_current_object_id() -> str | None:
            """
            Returns the Object ID of the signed-in user or service principal.
            """
            try:
                # Try Graph-based resolution first
                session = bm.GraphInitialization.get_session("global")
                me = session.get("https://graph.microsoft.com/v1.0/me")
                if me.status_code == 200:
                    return me.json().get("id")
            except Exception:
                pass

            try:
                client_id = bm.AzureIDs.client_id(project=mc.env.get("selected_project_name"))
                result = Subprocess.CMD.run([
                    "az", "ad", "sp", "show", "--id", client_id, "--query", "objectId", "--output", "tsv"
                ], capture_output=True, text=True, check=True, force_global_shell=True)
                return result.stdout.strip()
            except Exception as e:
                raise RuntimeWarning(f"[VaultSetup] Could not resolve objectId: {e}")

    class DatabaseSetup:
        """
        Handles provisioning and connection setup for Azure Database for PostgreSQL.

        Integrates with Azure CLI and environment config to:
        - Check for existing database instances
        - Create a PostgreSQL flexible server
        - Configure firewall, admin login, and network rules
        """

        @staticmethod
        def ensure_postgres_ready(project: str = None) -> dict:
            """
            Main entrypoint. Ensures a PostgreSQL flexible server exists and is reachable.

            Returns:
                dict: { name, fqdn, admin_login }
            """
            project = project or mc.env.get("selected_project_name")
            resource_group = bm.AzureIDs.resource_group(project)
            region = bm.AzureIDs.region(project)
            db_name = bm.AzureIDs.db_name(project)

            existing = bm.DatabaseSetup.get_fqdn(project)
            if existing:
                print(f"[DatabaseSetup] ✅ PostgreSQL already exists: {existing}")
                return existing

            print(f"[DatabaseSetup] ⚠️ Database not found. Attempting to create: {db_name}")
            return bm.DatabaseSetup.create_postgres(project)

        @staticmethod
        def create_postgres(project: str) -> dict:
            """
            Creates a PostgreSQL flexible server with secure defaults.

            Returns:
                dict: { name, fqdn, admin_login }
            """
            resource_group = bm.AzureIDs.resource_group(project)
            region = bm.AzureIDs.region(project)
            db_name = bm.AzureIDs.db_name(project)
            admin_user = "adminuser"
            admin_pass = Passwords.get(f"{db_name}.PASSWORD", project)

            print(f"[DatabaseSetup] 🚀 Creating PostgreSQL server: {db_name}")
            Subprocess.CMD.run([
                "az", "postgres", "flexible-server", "create",
                "--name", db_name,
                "--resource-group", resource_group,
                "--location", region,
                "--admin-user", admin_user,
                "--admin-password", admin_pass,
                "--sku-name", "Standard_B1ms",
                "--storage-size", "32",
                "--yes"
            ], capture_output=True, text=True, force_global_shell=True)

            fqdn = bm.DatabaseSetup.get_fqdn(project)["fqdn"]
            print(f"[DatabaseSetup] ✅ PostgreSQL server created: {fqdn}")

            return {
                "name": db_name,
                "fqdn": fqdn,
                "admin_login": admin_user
            }

        @staticmethod
        def get_fqdn(project: str) -> dict | None:
            """
            Returns FQDN of the existing server if it exists.

            Returns:
                dict: { fqdn } or None
            """
            try:
                db_name = bm.AzureIDs.db_name(project)
                resource_group = bm.AzureIDs.resource_group(project)
                result = Subprocess.CMD.run([
                    "az", "postgres", "flexible-server", "show",
                    "--name", db_name,
                    "--resource-group", resource_group,
                    "--query", "{fqdn: fullyQualifiedDomainName}",
                    "--output", "json"
                ], capture_output=True, text=True, force_global_shell=True)
                return json.loads(result.stdout.strip())
            except Exception:
                return None

    class AzureStrapper:
        """
        Manages Azure authentication and validation for a project, and routes the flow
        to relevant tasks such as Vault or Database setup based on the provided process argument.
        """

        @staticmethod
        def validate_azure_ids(project: str):
            """
            Ensures that all Azure IDs (Tenant ID, Subscription ID, etc.) are valid for the given project.
            If validation fails, the user is prompted to retry or stop.

            Args:
                project (str): The project name for scoping.
            """
            print(f"[AzureStrapper] Validating Azure IDs for project: {project}")

            retries = 0
            max_retries = 3

            while retries < max_retries:
                try:
                    # Attempt to validate all Azure IDs (tenant, subscription, etc.)
                    bm.AzureIDs.validate_all(project)
                    print(f"[AzureStrapper] ✅ Azure IDs validated for project: {project}")
                    return  # Exit the loop if validation succeeds

                except Exception as e:
                    print(f"[AzureStrapper] ❌ Failed to validate Azure IDs: {str(e)}")

                    # If retries are exhausted, raise an error and exit
                    if retries >= max_retries - 1:
                        print(f"[AzureStrapper] ❌ Max retries reached. Aborting.")
                        raise RuntimeError(
                            f"[AzureStrapper] Failed to validate Azure IDs after {max_retries} attempts.")

                    # Prompt the user for retry or quit
                    user_choice = input(f"Would you like to try again? (1 for Yes, 2 for No): ").strip()

                    if user_choice == "1":
                        retries += 1
                        print(f"[AzureStrapper] Retrying... Attempt {retries}/{max_retries}")

                        # Clear the cache using Azure CLI
                        print(f"[AzureStrapper] Clearing Azure CLI cache...")
                        try: Subprocess.CMD.run(["az", "logout"], force_global_shell=True)
                        except Exception: pass
                        time.sleep(2)  # Wait before retrying
                    elif user_choice == "2":
                        print(f"[AzureStrapper] User chose to stop. Aborting.")
                        raise RuntimeError(f"[AzureStrapper] User opted to stop after failure.")
                    else:
                        print("[AzureStrapper] Invalid choice. Please choose 1 to retry or 2 to stop.")
                        continue  # Ask again if the user enters an invalid response

        @staticmethod
        def route_to_process(process: str, project: str):
            """
            Routes the flow to the appropriate setup based on the provided process argument.

            Args:
                process (str): The process to route to ("vault" or "database").
                project (str): The project name for scoping.
            """
            if process == "vault":
                print(f"[AzureStrapper] Routing to Vault setup for project: {project}")
                bm.VaultSetup.ensure_vault_ready(project)
            elif process == "database":
                print(f"[AzureStrapper] Routing to Database setup for project: {project}")
                bm.DatabaseSetup.ensure_postgres_ready(project)
            else:
                raise ValueError(f"[AzureStrapper] ❌ Invalid process: {process}. Use 'vault' or 'database'.")

        @staticmethod
        def setup(project: str, process: str):
            """
            Validates all Azure IDs and routes to the corresponding process for the project.

            Args:
                project (str): The project name for scoping.
                process (str): The process to route to ("vault" or "database").
            """
            print(f"[AzureStrapper] Starting setup for project: {project}")

            # Step 1: Validate all Azure IDs (Tenant ID, Subscription ID, Client ID, etc.)
            bm.AzureStrapper.validate_azure_ids(project)

            # Step 2: Route to the appropriate process (Vault or Database setup)
            bm.AzureStrapper.route_to_process(process, project)

            print(f"[AzureStrapper] ✅ Setup completed for project: {project}")


bm = BackendMethods

import secrets
import string

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
    def sanitize(key: str) -> str:
        sanny_key = Sanitization.purge(key)
        return sanny_key

    @staticmethod
    def load_vault(project: str) -> SecretClient:
        """
        Initialize or retrieve the Azure SecretClient.
        This method is used to interact with Azure Key Vault.

        Returns:
            SecretClient: The Azure SecretClient instance for accessing the vault.
        """
        if Secrets._client:
            return Secrets._client

        url = bm.VaultSetup.get_url(project)
        if not url:
            raise RuntimeError(f"[Secrets] Vault URL not found for project: {project}")

        print("[Secrets] Vault URL found... Now ensuring permissions to modify...")
        bm.AzureClient.get_service_principal(bm.AzureIDs.client_id(project))

        try:
            # Using DefaultAzureCredential to authenticate
            client = SecretClient(vault_url=url, credential=DefaultAzureCredential())
            Secrets._client = client
            print("[Secrets] Vault successfully initialized!")
            return client
        except Exception as e:
            raise RuntimeError(f"[Secrets] Failed to initialize SecretClient: {e}")



    @staticmethod
    def store(name: str, value: str, project: str) -> None:
        """
        Persist the secret to Azure Key Vault.
        This method will overwrite any existing secret in Key Vault.

        Args:
            name (str): The name of the secret.
            value (str): The secret value.
            project (str): The project name.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        try:
            client = Secrets.load_vault(project)
            # Persist the secret
            secret = client.set_secret(secret_key, value)
            print(f"[Secrets] Successfully stored secret '{secret_key}' in Key Vault.")
            Secrets._cache[secret_key] = value  # Cache the value for local use
        except Exception as e:
            raise RuntimeError(f"[Secrets] Failed to store secret in Key Vault: {e}")

    @staticmethod
    def set(name: str, value: str, project: str, persist: bool = False) -> None:
        """
        Set the secret in cache and optionally persist it to Azure Key Vault.

        Args:
            name (str): The name of the secret.
            value (str): The secret value.
            project (str): The project name.
            persist (bool): Whether to persist the secret to Azure Key Vault. Default is False.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        # Store in local cache
        Secrets._cache[secret_key] = value
        print(f"[Secrets] Stored secret '{secret_key}' in cache.")

        # Optionally store the secret in Azure Key Vault
        if persist:
            Secrets.store(name, value, project)

    @staticmethod
    def has(name: str, project: str) -> bool:
        """
        Check if the secret exists in the cache or in Azure Key Vault.

        Args:
            name (str): The name of the secret.
            project (str): The project name.

        Returns:
            bool: True if the secret exists, False otherwise.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        if secret_key in Secrets._cache:
            return True

        try:
            client = Secrets.load_vault(project)
            client.get_secret(secret_key)  # Will raise if not found
            return True
        except Exception:
            return False

    @staticmethod
    def get(name: str, project: str, required: bool = True, store: bool = True) -> str | None:
        """
        Retrieve the secret from the cache or Azure Key Vault.

        Args:
            name (str): The name of the secret.
            project (str): The project name.
            required (bool): Whether the secret is required.
            store (bool): Whether to store the secret in the cache if found.

        Returns:
            str: The secret value.
        """
        secret_key = f"{project}.{name}"
        secret_key = Secrets.sanitize(secret_key)

        def return_secret(val):
            if store:
                Secrets._cache[secret_key] = val
            return val

        # Check cache first
        if secret_key in Secrets._cache:
            return return_secret(Secrets._cache[secret_key])

        # Check Key Vault
        try:
            client = Secrets.load_vault(project)
            val = client.get_secret(secret_key).value
            return return_secret(val)
        except Exception:
            pass

        if required:
            raise RuntimeError(f"[Secrets] Could not find secret: {secret_key}")
        return None

    @staticmethod
    def get_list(project: str) -> list[str]:
        """
        List all secrets in the Key Vault for a specific project.

        Args:
            project (str): The project name.

        Returns:
            list[str]: List of secret names.
        """
        client = Secrets.load_vault(project)
        prefix = f"{project}."
        results = []
        for prop in client.list_properties_of_secrets():
            if prop.name.startswith(prefix):
                try:
                    val = Secrets.get(prop.name[len(prefix):], project=project, required=False)
                    if val:
                        results.append(prop.name)
                except Exception:
                    continue
        return results

    @staticmethod
    def make_list(project: str) -> dict[str, str]:
        """
        Get all cached secrets for a specific project.

        Args:
            project (str): The project name.

        Returns:
            dict[str, str]: A dictionary of secret names and values.
        """
        prefix = f"{project}."
        return {
            key[len(prefix):]: val
            for key, val in Secrets._cache.items()
            if key.startswith(prefix)
        }

    @staticmethod
    def preload_cache(secrets: dict[str, str], project: str) -> None:
        """
        Preload multiple secrets into the cache.

        Args:
            secrets (dict): A dictionary of secret names and values.
            project (str): The project name.
        """
        if not isinstance(secrets, dict):
            raise TypeError("Expected a dictionary of secrets.")
        for k, v in secrets.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError(f"Secret keys/values must be strings. Got {k}={v}")
            Secrets._cache[f"{project}.{k}"] = v

    @staticmethod
    def clear_cache() -> None:
        """
        Clear the secret cache.
        """
        Secrets._cache.clear()
        Secrets._client = None

class Passwords:
    """
    A utility class for generating secure passwords with configurable options.
    """

    @staticmethod
    def generate_password(
            length: int = 16,
            min_length: int = 8,
            use_uppercase: bool = True,
            use_lowercase: bool = True,
            use_digits: bool = True,
            use_special_chars: bool = True
    ) -> str:
        """
        Generates a secure password that meets the specified complexity requirements.

        Args:
            length (int): Length of the password. Default is 16.
            min_length (int): Minimum length of the password. Default is 8.
            use_uppercase (bool): Whether to include uppercase letters. Default is True.
            use_lowercase (bool): Whether to include lowercase letters. Default is True.
            use_digits (bool): Whether to include digits. Default is True.
            use_special_chars (bool): Whether to include special characters. Default is True.

        Returns:
            str: The generated password.
        """
        print("[Passwords] Generating password now!")
        if length < min_length:
            raise ValueError(f"Password length should be at least {min_length} characters.")

        alphabet = ""
        if use_uppercase:
            alphabet += string.ascii_uppercase
        if use_lowercase:
            alphabet += string.ascii_lowercase
        if use_digits:
            alphabet += string.digits
        if use_special_chars:
            alphabet += string.punctuation

        if not alphabet:
            raise ValueError("At least one character type must be selected.")

        password = ''.join(secrets.choice(alphabet) for i in range(length))

        return password

    @staticmethod
    def generate_simple_password(length: int = 12) -> str:
        """
        Generates a simple password with default settings:
        - Length: 12 characters
        - Includes lowercase, uppercase, digits, and special characters.

        Args:
            length (int): Length of the password. Default is 12.

        Returns:
            str: The generated simple password.
        """
        return Passwords.generate_password(length=length)

    @staticmethod
    def validate_password(password: str) -> bool:
        """
        Validates the password complexity by checking its length and character types.

        Args:
            password (str): The password to validate.

        Returns:
            bool: True if the password meets the criteria, False otherwise.
        """
        if len(password) < 8:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.islower() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        if not any(c in string.punctuation for c in password):
            return False
        return True

    @staticmethod
    def get(name: str, project: str, length: int = 16) -> str:
        """
        Retrieves the password from the environment if it exists,
        otherwise generates and stores a new password for future use.

        Args:
            name: The password key for identifying it.
            project (str): The project name to associate the password with.
            length (int): Length of the password. Default is 16.

        Returns:
            str: The password (either retrieved from env or newly generated).
        """
        # Try to get the password from the environment
        print(f"[Passwords] Attempting to get password for {name} ...")
        password = Secrets.get(name, project, required=False, store=True)
        print(password)
        valid_password = None

        # If the password is not found, generate and store a new one
        if not password:
            print(f"[Passwords] No password found! Generating ...")
            password = Passwords.generate_password(length)
            Secrets.set(name, password, project, persist=True)

        if password:
            print(f"[Password] Password found.")
            valid_password = Passwords.validate_password(password)
            if valid_password is False: valid_password = Passwords.generate_password(length)

        print(f"[Passwords] Password successfully initialized!")

        return valid_password


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
    _registered = False

    @staticmethod
    @mileslib(retry=False)
    def auto_register_groups():
        """
        Auto-registers Click command groups for each valid project
        with a config TOML file.
        """
        if CLIDecorator._registered:
            print("[CLIDecorator] Skipping auto_register_groups — already called.")
            return
        CLIDecorator._registered = True

        for name, path in bm.ProjectUtils.discover_projects():
            print(f"[auto_register] Registering project group: {name}")

            def make_group(name: str, path: Path):
                @click.group(name=name, cls=ProjectAwareGroup)
                @click.pass_context
                def _grp(ctx):
                    ctx.ensure_object(dict)
                    ctx.obj["project_name"] = name
                    ctx.obj["project_path"] = path
                    bm.ProjectUtils.select_project(name=name, path=path)
                    print(f"[mileslib_settings.toml] Active project set to: {name}")

                return _grp

            if name not in CLIDecorator._projects:
                grp = make_group(name, path)
                CLIDecorator._projects[name] = grp
                CLIDecorator._global.add_command(grp)

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
            class Diagnostics:
                """
                Runs system diagnostics to ensure required tools are installed.
                """

                @staticmethod
                @mileslib_cli(project_only = False)
                def diagnostics_check(ctx, tool: str):
                    """
                    CLI: Runs diagnostic checks for a list of tools.

                    Args:
                        tool (list[str]): List of tools to check. Use multiple --tool flags.

                    Examples:
                        $ python -m mileslib diagnostics-check --tool azure --tool docker
                    """
                    print(f"[diagnostics] Checking tools: {tool}")
                    if tool == "all":
                        try:
                            Subprocess.ExternalDependency.ensure_all()
                        except Exception as e:
                            raise RuntimeError(f"Failed diagnostics check!: {e}")
                    try:
                        Subprocess.ExternalDependency.ensure(tool)
                    except Exception as e:
                        raise RuntimeError(f"Failed diagnostics check!: {e}")

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

                    # ─── ENV & Config ────────────────────────────────────────────────
                    proj_details = mc.Config.configify(proj_details_list)
                    for key in proj_details_list:
                        val = proj_details_list[key]
                        mc.env.write(f"{project_name}.{key}", f"{val}", replace_existing=True)

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
            class SecretsBootstrap:
                @staticmethod
                @mileslib_cli(project_only=True)
                def init_vault(ctx):
                    """
                    CLI entrypoint to initialize Azure Key Vault for the current project.

                    This will:
                    - Validate environment and Azure config
                    - Create the vault if missing
                    - Set up access policies
                    - Initialize the Secrets client for use

                    Args:
                        ctx (click.Context): Click context with project_name and project_path

                    Side Effects:
                        - Ensures vault exists and is usable
                        - Updates KEY_VAULT_URL in environment
                        - Logs status
                    """
                    project_name = ctx.obj["project_name"]
                    print(f"[SecretsBootstrap] Initializing vault for: {project_name}")

                    try:
                        uri = bm.VaultSetup.ensure_vault_ready(project_name)
                        print(f"[SecretsBootstrap] Vault ready at {uri}")
                        click.echo(f"✅ Vault initialized: {uri}")
                    except Exception as e:
                        print(f"[SecretsBootstrap] Failed to initialize vault: {e}")
                        raise click.ClickException(str(e))

            class Database:
                """
                CLI entrypoints for Azure PostgreSQL setup via MilesLib.
                """

                @staticmethod
                @mileslib_cli(project_only=True)
                def init_database(ctx):
                    """
                    Initializes Azure PostgreSQL for the active project.

                    - Checks for existing DB
                    - Creates a flexible server if needed
                    - Prints FQDN and admin login info
                    """
                    project = ctx.obj["project_name"]
                    print(f"[DatabaseSetup] Initializing database for project: {project}")
                    bm.AzureStrapper.setup(project, "database")
                    print(f"[DatabaseSetup] ✅ Successfully Initialized!")

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