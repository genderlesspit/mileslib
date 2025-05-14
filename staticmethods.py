from pathlib import Path
from typing import Any, List, Union, Mapping, Sequence, Callable, Tuple, Type
import json
import os
import importlib.util
import subprocess, sys
import logging as log

class StaticMethods: # For Internal Use
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
                log.info(f"{disp or 'Path'} initialized at {path}.")
            return path, True

        if create_if_missing:
            try:
                if path.suffix:  # assume it's a file
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("")
                    log.info(f"File created: {path}")
                else:  # assume it's a directory
                    path.mkdir(parents=True, exist_ok=True)
                    log.info(f"Directory created: {path}")
                return path, True
            except Exception as e:
                log.error(f"Failed to create {disp or 'path'}: {e}")
                return path, False

        if not quiet:
            log.warning(f"{disp or 'Path'} not found at {path}!")
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
    def timer(fn, *args, **kwargs):
        """Time the execution duration of a function call."""
        from time import perf_counter
        start = perf_counter()
        result = fn(*args, **kwargs)
        duration = perf_counter() - start
        log.info(f"Execution time: {duration:.2f}s")
        return result, duration

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
