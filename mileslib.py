from typing import Any, List, Union, Mapping, Sequence, Callable, Tuple, Type
import json
import importlib.util
import subprocess
import time
from typing import Iterator
import logging
from pathlib import Path
import sys
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime

class StaticMethods: # For Internal Use
    @staticmethod
    def attempt(
            fn,
            *args,
            retries: int = 3,
            backoff_base: int = 2,
            **kwargs
    ):
        """
        Retry `fn(*args, **kwargs)` up to `retries` times with exponential backoff.
        Raises the last exception if all attempts fail.
        """

        for attempt in range(1, retries + 1):
            try:
                return fn(*args, **kwargs)

            except Exception as e:
                last_exception = e
                print("Attempt failed")
                if attempt < retries:
                    delay = backoff_base ** (attempt - 1)
                    print("Backing off before retry")
                    time.sleep(delay)

        # all retries exhausted
        print("All attempts exhausted ... ")
        # re-raise last exception
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

    @staticmethod
    def restart(self):
        print("Restarting application...")
        python = sys.executable
        os.execv(python, [python] + sys.argv)

    @staticmethod
    def exists(path: Path,
               disp: str = None,
               quiet: bool = False,
               create_if_missing: bool = False
               ) -> tuple[Path, bool]:
        """
        Check if the given Path exists. Optionally create it if missing.

        Args:
            path (Path): The file or directory to check.
            disp (str): Optional display label for logging.
            quiet (bool): If True, suppress log output.
            create_if_missing (bool): Create file or directory if not found.

        Returns:
            tuple[Path, bool]: The Path and whether it exists (or was created).
        """
        path = Path(path)

        if path.exists():
            if not quiet:
                print(f"{disp or 'Path'} initialized at {path}.")
            return path, True

        if create_if_missing:
            try:
                if path.suffix:  # assume it's a file
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("")
                    print(f"File created: {path}")
                else:  # assume it's a directory
                    path.mkdir(parents=True, exist_ok=True)
                    print(f"Directory created: {path}")
                return path, True
            except Exception as e:
                print(f"Failed to create {disp or 'path'}: {e}")
                return path, False

        if not quiet:
            print(f"{disp or 'Path'} not found at {path}!")
        return path, False

    @staticmethod
    def dependency(dep: str, pack: str = None) -> bool:
        """Ensure a Python module is installed; install via pip if not."""
        try:
            if importlib.util.find_spec(dep) is None:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pack or dep])
                return True
            else:
                return True
        except Exception as e:
            return False

    @staticmethod
    def try_import(pack: str):
        """
        Attempt to import a package by name. Installs it if missing, then retries.

        Args:
            pack (str): Name of the package to import (e.g. "structlog")

        Returns:
            module: The imported module object

        Raises:
            RuntimeError: If the module cannot be imported after install attempts.
        """
        try:
            return importlib.import_module(pack)
        except ImportError:
            StaticMethods.dependency(pack)
            try:
                return StaticMethods.recall(lambda: importlib.import_module(pack), max_attempts=3,
                                 handled_exceptions=(ImportError,))
            except ImportError as e:
                raise RuntimeError(f"{pack} could not be properly loaded after installation.") from e

    @staticmethod
    def timer(label="operation"):
        """
        Decorator to log the duration of a function.

        Usage:
            @timer(label="fetch_data")
            def fetch_data(): ...
        """

        def decorator(fn):
            def wrapper(*args, **kwargs):
                start = time.perf_counter()
                result = fn(*args, **kwargs)
                duration = time.perf_counter() - start
                print(f"{duration:.3f}s")
                return result

            return wrapper

        return decorator

    @staticmethod
    def recall(fn: Callable, max_attempts: int = 3,
               handled_exceptions: Tuple[Type[BaseException]] = (Exception,)) -> Any:
        """
        Retry a function up to max_attempts times if handled exceptions occur.

        Args:
            fn: The function to retry.
            max_attempts: How many total attempts to make.
            handled_exceptions: Which exceptions to catch and retry on.

        Returns:
            The return value of the function, if successful.

        Raises:
            The last exception encountered, if all retries fail.
        """
        attempts = 0
        while attempts < max_attempts:
            try:
                return fn()
            except handled_exceptions as e:
                attempts += 1
                print(f"[Attempt {attempts}/{max_attempts}] Error: {e}")
                if attempts == max_attempts:
                    raise

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

    @staticmethod
    def validate_directory(path: str | Path) -> Path:
        """
        Ensures the provided directory exists. Attempts to create it if missing.

        Args:
            path (str | Path): The path to validate.

        Returns:
            Path: The validated directory path as a Path object.

        Raises:
            OSError: If directory creation fails.
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
        Ensures the provided file exists.

        Args:
            path (str | Path): The path to the file to check.

        Returns:
            Path: The validated file path as a Path object.

        Raises:
            FileNotFoundError: If the file does not exist.
            IsADirectoryError: If the path exists but is a directory.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: '{path}'")
        if path.is_dir():
            raise IsADirectoryError(f"Expected a file but found a directory at: '{path}'")
        return path

    @staticmethod
    def ensure_file_with_default(
            path: str | Path,
            default: dict | str,
            encoding: str = "utf-8"
    ) -> Path:
        """
        Ensures a file exists at the given path and has valid content.
        If the file is missing or empty, it is created/written with default content.

        Args:
            path (str | Path): Path to the file.
            default (dict | str): Default content (JSON or text).
            encoding (str): Encoding to use when writing the file.

        Returns:
            Path: The Path to the ensured file.

        Raises:
            TypeError: If default is not dict or str.
            OSError: If the file can't be created or written to.
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

sm = StaticMethods

class MilesLib:
    def __init__(self, pdir: Path = os.getcwd()):
        self.pdir = sm.validate_instance_directory(pdir)
        self.launch_time = datetime.utcnow()
        self.launch_time_file_name = self.launch_time.strftime("%Y-%m-%d_%H-%M-%S")

class MilesLogger:
    _configured = False
    _current_log_path = None
    _logger = None

    @staticmethod
    def try_import_loguru():
        loguru = sm.try_import("loguru")
        return loguru.logger

    @staticmethod
    def get_loguru():
        if not MilesLogger._configured:
            raise RuntimeError("Logger has not been initialized. Call init_logger() first.")
        return MilesLogger.try_import_loguru()

    @staticmethod
    def init_logger(
        log_dir: Path = Path("logs"),
        label: str = None,
        serialize: bool = True,
        pretty_console: bool = True,
        level: str = "INFO",
    ):
        loguru = MilesLogger.try_import_loguru()

        if MilesLogger._configured:
            return loguru

        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
        label = f"_{label}" if label else ""
        log_path = log_dir / f"{timestamp}{label}.log"

        if pretty_console:
            loguru.add(sys.stderr, level=level, enqueue=True)

        loguru.add(log_path, level=level, serialize=serialize, rotation="10 MB", enqueue=True)

        MilesLogger._logger = loguru  # ← Add this line
        MilesLogger._current_log_path = log_path
        MilesLogger._configured = True
        return loguru

    @staticmethod
    def get_logger():
        if not MilesLogger._configured:
            return MilesLogger.init_logger()
        return MilesLogger._logger

    @staticmethod
    def reset_logger():
        loguru = MilesLogger.try_import_loguru()
        loguru.remove()
        MilesLogger._current_log_path = None
        MilesLogger._configured = False
        MilesLogger._logger = None

log = MilesLogger.get_logger()
log_path = MilesLogger._current_log_path
log_exists = MilesLogger._configured

class Config:
    def __init__(self, inst):
        """
        Initializes the Config class for the client. A subclass of the main MilesLib instance.
        Validates the incoming instance and its directory before proceeding.
        """
        StaticMethods.validate_instance(inst=inst)
        self.m = inst
        self.pdir = StaticMethods.validate_instance_directory(pdir=self.m.pdir)

        # Directory Initialization
        self.cfg_dir = os.path.join(self.pdir, "config")
        StaticMethods.validate_directory(self.cfg_dir)
        self.cfg_file = self.build_config(self.cfg_dir)

    @staticmethod
    def build_config(cfg_dir):
        file = os.path.join(cfg_dir, "config.json")
        if os.path.exists(file):
            build: Path = StaticMethods.validate_file(file)
            return build
        else:
            build: Path = StaticMethods.ensure_file_with_default("tests/.dev/config/config.json",
                                                                 default={"app_name": "MilesApp", "version": "1.0"})
            return build

    def get(self, *args: str | list | tuple):
        file = self.cfg_file
        for arg in args:
            if not isinstance(arg, (str, int)):
                raise TypeError(f"Invalid path for config.get(): {arg!r} must be str, list, or int")

        def load_and_traverse():
            if os.stat(file).st_size == 0:
                StaticMethods.ensure_file_with_default("tests/.dev/config/config.json",
                                                       default={"app_name": "MilesApp", "version": "1.0"})
            with open(file, "r", encoding="utf-8") as f:
                config_data = json.load(f)

            return StaticMethods.traverse_dictionary(config_data, *args)

        try:
            setting = StaticMethods.recall(
                fn=load_and_traverse,
                max_attempts=3,
                handled_exceptions=(json.JSONDecodeError, FileNotFoundError)
            )

            if setting is None:
                raise Exception(f"Requested setting not found in {file}. Please amend.")
            return setting

        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON in {file}: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading {file}: {e}")

if __name__ == "__main__":
    # CLI bootstraps to mileslib.cli.main:cli
    from cli.main import cli
    cli()