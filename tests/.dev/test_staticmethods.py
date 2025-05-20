import shutil
from unittest import mock
import pytest
from mileslib import StaticMethods as sm
import importlib.util
import requests
from typing import Any, List, Union, Mapping, Sequence, Callable, Tuple, Type, Optional
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

    class ErrorHandling:
        @staticmethod
        def timer(label="operation"):
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
            Retry `fn(*args, **kwargs)` with timing and logging using the internal timer decorator.
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

    class PathUtil:
        @staticmethod
        def normalize_path(p: str | Path) -> Path:
            return Path(p)

        @staticmethod
        def ensure_path(
                path: str | Path,
                is_file: bool = False,
                create: bool = False,
                verbose: bool = False
        ) -> tuple[Path, bool]:
            """
            Ensures a file or directory exists at the given path.

            Args:
                path (str | Path): Path to check.
                is_file (bool): If True, treat path as a file (create parent dir).
                create (bool): If True, create the file or directory if missing.
                verbose (bool): If True, print creation/log output.

            Returns:
                (Path, bool): The normalized path and whether it exists or was created.
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
            Ensures a file exists at the given path and has valid content.
            If the file is missing or empty, it is created/written with default content.
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
            Ensures the provided directory exists. Attempts to create it if missing.
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
            Ensures the provided file exists and is not a directory.
            """
            path = Path(path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: '{path}'")
            if path.is_dir():
                raise IsADirectoryError(f"Expected a file but found a directory at: '{path}'")
            return path

    normalize_path = PathUtil.normalize_path
    ensure_path = PathUtil.ensure_path
    ensure_file_with_default = PathUtil.ensure_file_with_default
    validate_directory = PathUtil.validate_directory
    validate_file = PathUtil.validate_file

    class Logger:
        _configured = False
        _current_log_path = None
        _logger = None

        @staticmethod
        def try_import_loguru():
            loguru = sm.try_import("loguru")
            return loguru.logger

        @staticmethod
        def get_loguru():
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
            if not StaticMethods.Logger._configured:
                return StaticMethods.Logger.init_logger()
            return StaticMethods.Logger._logger

        @staticmethod
        def reset_logger():
            loguru = StaticMethods.Logger.try_import_loguru()
            loguru.remove()
            StaticMethods.Logger._current_log_path = None
            StaticMethods.Logger._configured = False
            StaticMethods.Logger._logger = None

    log = Logger.get_logger()
    log_path = Logger._current_log_path
    log_exists = Logger._configured

    class Requests:
        @staticmethod
        @sm.timer(label="http_get")
        def http_get(url: str, retries: int = 3) -> requests.Response:
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
        @sm.timer(label="http_post")
        def http_post(url: str, data: dict, retries: int = 3) -> requests.Response:
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

    class Validation:
        @staticmethod
        def validate_instance(inst):
            """Checks if the incoming instance is valid and not None."""
            if inst is None:
                raise RuntimeError("Instance passed to Config is None.")
            if not hasattr(inst, "__dict__"):
                raise RuntimeError(f"Invalid instance passed to Config: {type(inst).__name__}")

        @staticmethod
        def validate_instance_directory(pdir) -> Path:
            """
            Ensures the instance has a valid `pdir` path.
            Accepts string or Path. Returns Path.
            """
            if isinstance(pdir, str):
                pdir = Path(pdir)
            if not isinstance(pdir, Path):
                raise TypeError("`.pdir` must be a string or pathlib.Path.")
            if not pdir.exists():
                raise FileNotFoundError(f"Directory does not exist: {pdir}")
            return pdir

    class Parsing:
        @staticmethod
        def traverse_dictionary(data: Any, *keys: Union[str, int], default: Any = None) -> Any:
            """
            Traverse nested dictionaries (and optionally lists) using a list of keys/indexes.

            Parameters:
                data: The initial data structure (dict or list).
                keys: A list of keys or indexes to access nested values.
                default: What to return if any key is not found.

            Returns:
                The final nested value or default if the path doesn't exist.
            """
            current = data
            for key in keys:
                try:
                    if isinstance(current, Mapping) and key in current:
                        current = current[key]
                    elif isinstance(current, Sequence) and not isinstance(current, str):
                        current = current[key]
                    else:
                        return default
                except (KeyError, IndexError, TypeError):
                    return default
            return current

    class Github:
        @staticmethod
        def get_file(
                mileslib,
                *path_parts: str,
                repo_url: str,
                dest_dir: Path,
                as_text: bool = True,
                save_as: str = None,
                token: str = None,
                quiet: bool = False,
                no_save: bool = False,
        ) -> str | bytes | None:
            """
            Fetch a file from GitHub and optionally save it locally.

            Args:
                mileslib: MilesLib instance for logging and requests
                path_parts: Path components (e.g., "config", "config.json")
                repo_url: Base GitHub URL
                dest_dir: Where to save the file (default: assembled from path_parts)
                as_text: Return as string if True, else bytes
                save_as: Optional name to save as
                token: GitHub access token (optional)
                quiet: Suppress logging
                no_save: If True, return content without writing to disk

            Returns:
                Content as str or bytes if `no_save` is True, otherwise saved content
            """
            full_url = "/".join([repo_url.rstrip("/")] + [p.strip("/") for p in path_parts])
            local_path = dest_dir / (save_as or os.path.join(*path_parts))

            headers = {"Authorization": f"token {token}"} if token else {}

            try:
                content = mileslib.request(full_url, headers=headers, as_text=as_text,
                                           message="Downloading from GitHub")
                if content is None:
                    return None

                if no_save:
                    return content

                # Save to disk
                os.makedirs(local_path.parent, exist_ok=True)
                mode = "w" if as_text else "wb"
                with open(local_path, mode, encoding="utf-8" if as_text else None) as f:
                    f.write(content)
                mileslib.log.info(f"Saved GitHub file to {local_path}")
                return content

            except Exception as e:
                mileslib.log.warning(f"Failed to retrieve from GitHub: {e}")
                return None

        @staticmethod
        def get_remote_config(mileslib, repo_url: str, token: str = None) -> dict:
            """
            Fetch remote config.json from GitHub and parse as JSON.

            Returns:
                Parsed JSON dictionary
            """
            raw = StaticMethods.Github.get_file(
                mileslib,
                "config", "config.json",
                repo_url=repo_url,
                dest_dir=Path(mileslib.pdir) / "config",
                as_text=True,
                token=token,
                no_save=True
            )
            try:
                return json.loads(raw)
            except Exception as e:
                mileslib.crash(f"Could not load remote config.json: {e}")
                return {}

        @staticmethod
        def check_version_update(local_version: str, remote_version: str, mileslib=None) -> bool:
            """
            Compare two versions using PEP 440 rules.

            Returns:
                True if remote_version is newer than local_version
            """
            if mileslib:
                mileslib.log.info(f"Comparing local {local_version} vs remote {remote_version}")
            return version.parse(remote_version) > version.parse(local_version)

        @staticmethod
        def install_full_update(mileslib, repo_url: str, dest_dir: Path, token: str = None):
            """
            Downloads and extracts the full repo into `dest_dir`.
            """
            zip_url = repo_url.replace("raw.githubusercontent.com", "github.com").replace(
                "/master", "/archive/refs/heads/master.zip"
            )
            headers = {"Authorization": f"token {token}"} if token else {}

            try:
                mileslib.close_log()
                response = requests.get(zip_url, headers=headers, stream=True)
                response.raise_for_status()

                with tempfile.TemporaryDirectory() as tmpdir:
                    zip_path = Path(tmpdir) / "repo.zip"
                    with open(zip_path, "wb") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)

                    with zipfile.ZipFile(zip_path, "r") as zip_ref:
                        zip_ref.extractall(tmpdir)

                    repo_root = next(Path(tmpdir).glob("*/"))
                    for item in repo_root.iterdir():
                        target = dest_dir / item.name
                        if item.is_dir():
                            if target.exists():
                                shutil.rmtree(target)
                            shutil.copytree(item, target)
                        else:
                            shutil.copy2(item, target)

                mileslib.open_log()
                mileslib.log.info("✅ GitHub update complete. Restarting...")
                mileslib.restart()

            except Exception as e:
                mileslib.crash(f"Update failed: {e}")


sm = StaticMethods

## Error Handling Class
import pytest
from unittest.mock import Mock, patch
from typing import Type

ErrorHandling = StaticMethods.ErrorHandling

def test_attempt_success_first_try():
    fn = Mock(return_value="ok")
    result = ErrorHandling.attempt(fn)
    assert result == "ok"
    fn.assert_called_once()

def test_attempt_retries_then_success():
    fn = Mock(side_effect=[ValueError("fail1"), ValueError("fail2"), "success"])
    with patch("time.sleep") as sleep:
        result = ErrorHandling.attempt(fn, retries=3, backoff_base=1, handled_exceptions=(ValueError,))
    assert result == "success"
    assert fn.call_count == 3
    assert sleep.call_count == 2  # two backoffs before success

def test_attempt_all_fail_then_raise():
    fn = Mock(side_effect=RuntimeError("fail always"))
    with patch("time.sleep") as sleep, pytest.raises(RuntimeError, match="fail always"):
        ErrorHandling.attempt(fn, retries=2, backoff_base=1, handled_exceptions=(RuntimeError,))
    assert fn.call_count == 2
    assert sleep.call_count == 1

def test_attempt_ignores_unhandled_exception():
    fn = Mock(side_effect=ValueError("unexpected"))
    with pytest.raises(ValueError, match="unexpected"):
        ErrorHandling.attempt(fn, retries=3, handled_exceptions=(KeyError,))  # should not retry
    assert fn.call_count == 1

def test_attempt_no_backoff_if_base_none():
    fn = Mock(side_effect=[Exception("fail"), "pass"])
    with patch("time.sleep") as sleep:
        result = ErrorHandling.attempt(fn, retries=2, backoff_base=None)
    assert result == "pass"
    assert sleep.call_count == 0

@pytest.mark.parametrize("value,expected", [
    ("hello", str),
    (42, int),
    ([1, 2], list),
])
def test_check_input_valid(value, expected):
    # Should not raise
    ErrorHandling.check_input(value, expected)

@pytest.mark.parametrize("value,expected", [
    (42, str),
    ("wrong", (int, float)),
])
def test_check_input_invalid(value, expected):
    with pytest.raises(TypeError):
        ErrorHandling.check_input(value, expected, label="TestArg")
