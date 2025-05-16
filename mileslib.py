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

class MilesLib:
    def __init__(self, pdir: str = os.getcwd()):
        self.sm = StaticMethods()
        self.pdir = self.sm.validate_instance_directory(pdir)
        self.launch_time = datetime.utcnow()
        self.launch_time_file_name = self.launch_time.strftime("%Y-%m-%d_%H-%M-%S")
        self.logger = Logger(inst=self)

class Logger:
    def __init__(self, inst):
        """
        Logger operates on a passed-in test_Main instance.
        :param inst Argument for instance passed through the classname.
        """
        self.sm.validate_instance(inst=inst)
        self.m = inst
        self.pdir = self.m.pdir
        self.log_stamp = self.m.launch_time.strftime("%Y-%m-%d_%H-%M-%S")

        self.log_dir = self.sm.validate_directory(self.m.pdir / "logs")
        self.class_dir = self.log_dir #alt for avoiding refactoring code
        self.log_file_dir = self.create_log_file()
        self.logger = self.setup_structlog_logger(self.log_file_dir)

        #ID
        self._id = self.pdir.name

        #Contents
        self.contents = list(self.pdir.iterdir())

    def __getattr__(self, name):
        if hasattr(self.logger, name):
            return getattr(self.logger, name)
        raise AttributeError(f"'Logger' object has no attribute '{name}'")

    ### Dynamic Methods ###
    def create_log_file(self):
        was_log_file_created = False #yet....
        try:
            log_file_dir , was_log_file_created = self.sm.exists(path=Path(self.log_dir / f"{self.log_stamp}.log"),create_if_missing=True)
            return Path(log_file_dir)
        except Exception as e:
            raise RuntimeError(f"sm.exists() is broken, could not create {e}") if was_log_file_created is False else None

    ### Logger Methods ###
    @classmethod
    def class_method(cls):
        """
        Placeholder classname method.
        - Uses classname reference (`cls`)
        """
        return cls.__name__

    ### Static Methods ###
    @staticmethod
    def close_handlers() -> None:
        """
        Close all logging handlers associated with this logger.
        Useful for cleanup in tests or before deleting log files.
        """
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            try:
                handler.flush()
                handler.close()
            except Exception:
                pass
        root_logger.handlers.clear()

    @staticmethod
    def setup_structlog_logger(log_path: Path):
        """
        Configure a structlog-based logger with file rotation and JSON output.

        Attempts to import structlog, installing it if necessary. Uses StaticMethods.recall
        to retry import after installation. Sets up both console and file handlers.

        Args:
            log_path (Path): The target path for log file output.

        Returns:
            BoundLogger: A configured structlog logger instance.
        """

        def import_structlog():
            return __import__("structlog")

        # Try importing structlog, install if missing, retry using recall
        try:
            structlog = import_structlog()
        except ImportError:
            StaticMethods.dependency("structlog")
            try:
                structlog = StaticMethods.recall(import_structlog, max_attempts=3, handled_exceptions=(ImportError,))
            except ImportError as e:
                raise RuntimeError("structlog could not be properly loaded after installation.") from e

        # Prepare log directory
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Set up file and console handlers
        handlers = [
            RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=5),
            logging.StreamHandler()
        ]

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.handlers.clear()  # critical!
        for h in handlers:
            root_logger.addHandler(h)

        # Configure structlog
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )

        return structlog.get_logger()

    def __repr__(self):
        return (
            f"<Logger id='{self._id}' "
            f"path='{self.log_dir}' "
            f"file='{self.log_file_dir.name}'>"
        )

    def __str__(self) -> str:
        """
        Return a human-readable string describing the object.

        Example:
            Boilerplate at '/home/user/project' with 5 items
        """
        return f"{self.__class__.__name__} at '{self.class_dir}' with {len(self)} items"

    def __bool__(self) -> bool:
        """
        Return True if the backing directory exists and is valid.

        Enables:
            if obj: ...
        """
        return self.class_dir.exists() and self.class_dir.is_dir()

    def __eq__(self, other: object) -> bool:
        """
        Check if two Logger instances point to the same directory.

        Returns:
            bool: True if same type and same path.
        """
        return isinstance(other, Logger) and self.class_dir == other.class_dir

    def __len__(self) -> int:
        """
        Return the number of files/subdirs inside the directory.

        Returns:
            int: Number of immediate entries in the path.
        """
        return len(self.contents)

    def __contains__(self, filename: str) -> bool:
        """
        Check if a file with the given name exists inside the directory.

        Args:
            filename (str): Name to check for (not full path).

        Returns:
            bool: True if file exists by name.
        """
        return any(f.name == filename for f in self.contents)

    def __getitem__(self, index: int) -> Path:
        """
        Allow indexed access to contents (like a list).

        Args:
            index (int): Position in the contents list.

        Returns:
            Path: File or directory at that position.
        """
        return self.contents[index]

    def __iter__(self) -> Iterator[Path]:
        """
        Make the object iterable over its contents.

        Returns:
            Iterator[Path]: Iterator over Path objects inside pdir.
        """
        return iter(self.contents)

    def refresh(self) -> None:
        """
        Reload the contents from disk.
        Use after files have changed outside the object context.
        """
        self.contents = list(self.class_dir.iterdir())

if __name__ == "__main__":
    #Miles Lib Instance
    m = MilesLib()