import importlib.util
import requests
from typing import Any, Union, Callable, Tuple, Type, Optional
import importlib.util
import subprocess
import time
from pathlib import Path
import sys


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
        def recall(fn: Callable, fix: Callable, *args, **kwargs):
            """
            Calls a function with retry logic and a required fix callback.

            This is a convenience wrapper around `attempt()` that enforces a `fix` function.
            Useful when you want to always attempt recovery before retrying.

            Args:
                fn (Callable): The function to execute.
                fix (Callable): A callback function to run once upon the first failure.
                *args: Positional arguments for `fn`.
                **kwargs: Keyword arguments passed to `attempt`.

            Returns:
                Any: The result of `fn(*args, **kwargs)` if successful.

            Raises:
                RuntimeError: If the fix fails or if the function continues to fail after fix.
                BaseException: The last caught exception if all attempts fail.
            """
            # simply forward to attempt
            return StaticMethods.ErrorHandling.attempt(fn, fix=fix, *args, **kwargs)

        @staticmethod
        def attempt(
            fn: Callable,
            *args,
            retries: int = 3,
            fix: Optional[Callable[[], None]] = None,
            backoff_base: Optional[int] = None,
            handled_exceptions: Tuple[Type[BaseException], ...] = (Exception,),
            label: str = "operation",
            **kwargs
        ) -> Any:
            """
            Executes a function with retry logic, optional recovery callback, and timing.

            The function is decorated with a timing wrapper. If it raises any of the
            specified `handled_exceptions`, it will retry up to `retries` times.
            If a `fix` callback is provided, it will be executed once after the first failure.

            Exponential backoff is supported if `backoff_base` is set.

            Args:
                fn (Callable): The function to execute.
                *args: Positional arguments to pass to the function.
                retries (int): Maximum number of attempts (default: 3).
                fix (Callable, optional): One-time recovery callback to run after first failure.
                backoff_base (int, optional): Base for exponential backoff (e.g., 2 = 1s, 2s, 4s).
                handled_exceptions (tuple): Exceptions to catch and retry (default: Exception).
                label (str): Label for logging and timing context.
                **kwargs: Additional keyword arguments for the function.

            Returns:
                Any: The result of the function if any attempt succeeds.

            Raises:
                RuntimeError: If the `fix` function fails or is reused after one attempt.
                BaseException: The last encountered exception if all attempts fail.
            """
            timed_fn = StaticMethods.ErrorHandling.timer(label)(fn)
            last_exception = None
            attempted_fix = False
            label = label or getattr(fn, "__name__", "operation")

            for attempt in range(1, retries + 1):
                try:
                    result = timed_fn(*args, **kwargs)
                    print(f"[{label}] Success on attempt {attempt}")
                    return result
                except handled_exceptions as e:
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

StaticMethods.log = StaticMethods.Logger.get_logger() # this is for testing purposes only
sm = StaticMethods
log = StaticMethods.Logger.get_logger()

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
         mock.patch("milessubprocess.check_call") as mock_call:
        assert StaticMethods.Dependencies._dependency("fakepkg") is True
        mock_call.assert_called_once()


def test_dependency_install_failure():
    with mock.patch("importlib.util.find_spec", return_value=None), \
         mock.patch("milessubprocess.check_call", side_effect=Exception("fail")):
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

    with mock.patch("milessubprocess.check_call"), \
        mock.patch("importlib.util.find_spec", return_value=None), \
        mock.patch.object(StaticMethods.ErrorHandling, "attempt", return_value=dummy), \
        mock.patch("importlib.import_module", side_effect=import_side_effect):
            result = StaticMethods.Dependencies.try_import("something")
            assert result is dummy


def test_try_import_fails_after_install():
    # patch install and find_spec, and patch recall to also fail
    with mock.patch("milessubprocess.check_call"), \
        mock.patch("importlib.util.find_spec", return_value=None), \
        mock.patch.object(StaticMethods.ErrorHandling, "attempt", side_effect=ImportError("still broken")):

        # now simulate importlib always failing
        with mock.patch("importlib.import_module", side_effect=ImportError("initial fail")):
            with pytest.raises(RuntimeError, match="could not be properly loaded"):
                StaticMethods.Dependencies.try_import("badmod")

## PathUtil Tests

import pytest

PathUtil = StaticMethods.PathUtil

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

@pytest.fixture
def config_data():
    return {
        "DEBUG": True,
        "SECRET_KEY": "changeme",
        "PORT": 8000
    }

@pytest.fixture
def cfg_dir(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    return cfg


def test_txt_write_and_read(cfg_dir):
    path = cfg_dir / "example.txt"
    content = "Hello, FileIO!"

    # Write
    StaticMethods.FileIO.write(path, "txt", {"content": content}, overwrite=True)
    assert path.exists()

    # Read
    result = StaticMethods.FileIO.read(path, "txt")
    assert "content" in result
    assert result["content"] == content


def test_txt_read_missing_file(cfg_dir):
    path = cfg_dir / "missing.txt"
    result = StaticMethods.FileIO.read(path, "txt")
    assert result == {}


def test_txt_write_invalid_format_raises(cfg_dir):
    path = cfg_dir / "bad.txt"

    # Missing 'content' key
    with pytest.raises(ValueError):
        StaticMethods.FileIO.write(path, "txt", {"not_content": "oops"}, overwrite=True)

    # Not a dict at all
    with pytest.raises(ValueError):
        StaticMethods.FileIO.write(path, "txt", "just a string", overwrite=True)

def test_toml_write_and_read(cfg_dir, config_data):
    path = cfg_dir / "settings.toml"
    StaticMethods.FileIO.write(path, "toml", config_data, overwrite=True)

    loaded = StaticMethods.FileIO.read(path, "toml")
    assert loaded == {"default": config_data}

def test_toml_merge_preserves_existing(cfg_dir):
    path = cfg_dir / "settings.toml"
    existing = {"default": {"DEBUG": False, "KEEP": "yes"}}
    import toml
    path.write_text(toml.dumps(existing), encoding="utf-8")

    new = {"DEBUG": True, "SECRET_KEY": "new"}
    StaticMethods.FileIO.write(path, "toml", new, overwrite=False, replace_existing=False)

    result = toml.load(path)["default"]
    assert result["KEEP"] == "yes"
    assert result["DEBUG"] is False  # kept existing
    assert result["SECRET_KEY"] == "new"

def test_toml_merge_replaces(cfg_dir):
    path = cfg_dir / "settings.toml"
    import toml
    path.write_text(toml.dumps({"default": {"A": 1}}), encoding="utf-8")

    StaticMethods.FileIO.write(path, "toml", {"A": 2}, overwrite=False, replace_existing=True)
    loaded = toml.load(path)["default"]
    assert loaded["A"] == 2

def test_json_write_and_read(cfg_dir, config_data):
    path = cfg_dir / "config.json"
    StaticMethods.FileIO.write(path, "json", config_data, overwrite=True)

    loaded = StaticMethods.FileIO.read(path, "json")
    assert loaded == {"default": config_data}

def test_env_write_and_read(cfg_dir):
    path = cfg_dir / ".env"
    data = {"FOO": "bar", "DEBUG": "true"}

    StaticMethods.FileIO.write(path, "env", data, overwrite=True)
    loaded = StaticMethods.FileIO.read(path, "env")

    assert loaded["FOO"] == "bar"
    assert loaded["DEBUG"] == "true"

def test_merge_replaces_values():
    base = {"A": 1, "B": 2}
    new = {"B": 99, "C": 3}
    merged = StaticMethods.FileIO._merge(base, new, replace=True)
    assert merged == {"A": 1, "B": 99, "C": 3}

def test_merge_preserves_values():
    base = {"A": 1, "B": 2}
    new = {"B": 99, "C": 3}
    merged = StaticMethods.FileIO._merge(base, new, replace=False)
    assert merged == {"A": 1, "B": 2, "C": 3}

def test_read_unsupported_raises(cfg_dir):
    path = cfg_dir / "unsupported.ini"
    path.write_text("some=data")
    with pytest.raises(ValueError):
        StaticMethods.FileIO.read(path, "ini")

def test_write_unsupported_raises(cfg_dir, config_data):
    path = cfg_dir / "unsupported.ini"
    with pytest.raises(ValueError):
        StaticMethods.FileIO.write(path, "ini", config_data)

import pytest
import toml
import json
from pathlib import Path
from tests.mileslib_core import StaticMethods as sm

@pytest.fixture
def cfg_dir(tmp_path):
    path = tmp_path / "config"
    path.mkdir()
    return path

def test_config_directory_resolves(cfg_dir):
    assert StaticMethods.Config._get_config_dir(cfg_dir.parent) == cfg_dir

def test_find_settings_file_priority(cfg_dir):
    (cfg_dir / "settings.toml").write_text("[default]\n")
    (cfg_dir / "settings.yaml").write_text("")
    found = StaticMethods.Config._find_settings_file(cfg_dir)
    assert found.name == "settings.toml"

def test_find_settings_file_global_filters_dotfiles(cfg_dir):
    (cfg_dir / ".secrets.toml").write_text("")
    (cfg_dir / ".env").write_text("")
    assert StaticMethods.Config._find_settings_file(cfg_dir, is_global=True) is None

def test_build_creates_and_reads_default(cfg_dir):
    pdir = cfg_dir.parent
    config = StaticMethods.Config.build(pdir=pdir)

    settings_path = cfg_dir / "settings.toml"
    print(f"\n[DEBUG] settings.toml contents:\n{settings_path.read_text(encoding='utf-8')}")

    # Updated to reflect nested structure
    assert config.get("default", {}).get("valid") is True

def test_build_with_custom_filename(cfg_dir):
    pdir = cfg_dir.parent
    custom_name = "custom.toml"
    config = StaticMethods.Config.build(pdir=pdir, file_name=custom_name)

    file_path = cfg_dir / custom_name
    print(f"\n[DEBUG] {custom_name} contents:\n{file_path.read_text(encoding='utf-8')}")

    assert file_path.exists()
    assert config["default"]["valid"] is True

def test_config_get_nested_and_default(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "config.json").write_text(json.dumps({"default": {"a": {"b": 123}}}))

    assert StaticMethods.Config.get("a", "b", pdir=tmp_path) == 123
    assert StaticMethods.Config.get("x", pdir=tmp_path, default="fallback") == "fallback"

    with pytest.raises(RuntimeError):
        StaticMethods.Config.get("a", "b", pdir=tmp_path, expected=999)

def test_config_require_valid_and_invalid(tmp_path, monkeypatch):
    monkeypatch.setattr(StaticMethods.Config, "REQUIRED_KEYS", ["x", "y"], raising=False)
    monkeypatch.setattr(StaticMethods.Config, "DENYLIST", ["bad"], raising=False)

    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "config.json").write_text(json.dumps({"default": {"x": 1, "y": "bad"}}))

    with pytest.raises(RuntimeError) as exc:
        StaticMethods.Config.require(["y"], root=None, pdir=tmp_path)
    assert "Invalid" in str(exc.value)

    with pytest.raises(RuntimeError) as exc:
        StaticMethods.Config.require(["z"], root=None, pdir=tmp_path)
    assert "Missing" in str(exc.value)

def test_write_overwrites_toml(cfg_dir):
    path = cfg_dir.parent
    StaticMethods.Config.write(pdir=path, file_name="settings.toml", data={"valid": True}, overwrite=True)
    assert (cfg_dir / "settings.toml").exists()


def test_write_merges_preserves_existing(cfg_dir):
    path = cfg_dir.parent
    f = cfg_dir / "settings.toml"
    f.write_text("[default]\nKEEP='yes'\n", encoding="utf-8")
    StaticMethods.Config.write(pdir=path, data={"valid": True}, overwrite=False, replace_existing=False)
    parsed = toml.load(f)
    assert parsed["default"].get("KEEP", ) == "yes"


def test_write_merges_replaces_existing(cfg_dir):
    path = cfg_dir.parent
    f = cfg_dir / "settings.toml"
    f.write_text("[default]\nfoo='bar'\n")
    StaticMethods.Config.write(pdir=path, data={"foo": "baz"}, overwrite=False, replace_existing=True)
    parsed = toml.load(f)
    assert parsed["default"].get("foo", ) == "baz"


def test_write_replaces_file_completely(cfg_dir):
    path = cfg_dir.parent
    f = cfg_dir / "settings.toml"
    f.write_text("[default]\nremove='this'\n")
    StaticMethods.Config.write(pdir=path, data={"clean": True}, overwrite=True)
    parsed = toml.load(f)
    assert "remove" not in parsed["default"]
    assert parsed["default"].get("clean", ) is True

Logger = StaticMethods.Logger

@pytest.fixture(autouse=True)
def reset_logger_after_test():
    yield
    Logger.reset_logger()

def test_logger_resets_state():
    Logger._configured = True
    Logger._current_log_path = Path("fake.log")
    Logger._logger = object()

    Logger.reset_logger()

    assert Logger._configured is False
    assert Logger._current_log_path is None
    assert Logger._logger is None

from loguru import logger as loguru_logger

def test_logger_init_creates_log_file(tmp_path):
    logger = Logger.init_logger(log_dir=tmp_path, label="testlog", serialize=False)

    assert Logger._configured is True
    assert isinstance(Logger._current_log_path, Path)
    assert Logger._current_log_path.exists()

    # Write and flush a log message
    logger.info("Test log message")
    loguru_logger.complete()  # force background logging to finish

    contents = Logger._current_log_path.read_text(encoding="utf-8")
    assert isinstance(contents, str)
    assert "Test log message" in contents

def test_logger_reuses_existing_logger(tmp_path):
    logger1 = Logger.init_logger(log_dir=tmp_path, label="one", serialize=False)
    path1 = Logger._current_log_path

    logger2 = Logger.init_logger(log_dir=tmp_path, label="two", serialize=False)
    path2 = Logger._current_log_path

    assert logger1 is logger2
    assert path1 == path2  # still using original log path

def test_get_logger_auto_initializes(tmp_path, monkeypatch):
    monkeypatch.setattr(Logger, "_configured", False)

    # Set default log directory to tmp_path for isolation
    monkeypatch.setattr(sm, "ensure_path", lambda path, is_file=False, create=True: (tmp_path, None))

    logger = Logger.get_logger()
    assert Logger._configured is True
    assert Logger._logger is not None

def test_get_loguru_errors_if_not_initialized(monkeypatch):
    monkeypatch.setattr(Logger, "_configured", False)
    with pytest.raises(RuntimeError, match="Logger has not been initialized"):
        Logger.get_loguru()

def test_try_import_loguru_returns_logger():
    loguru_logger = Logger.try_import_loguru()
    assert hasattr(loguru_logger, "info")
    assert hasattr(loguru_logger, "debug")

def test_http_get_success(requests_mock):
    url = "https://example.com/data"
    requests_mock.get(url, )

    resp = StaticMethods.Requests.http_get(url)
    assert resp.status_code == 200
    assert resp.text == "OK"

def test_http_post_success(requests_mock):
    url = "https://example.com/post"
    payload = {"key": "value"}
    requests_mock.post(url, json={"result": "ok"}, status_code=200)

    resp = StaticMethods.Requests.http_post(url, data=payload)
    assert resp.status_code == 200
    assert resp.json() == {"result": "ok"}

def test_http_get_invalid_url_type():
    with pytest.raises(TypeError):
        StaticMethods.Requests.http_get(12345)

def test_http_post_invalid_data_type():
    with pytest.raises(TypeError):
        StaticMethods.Requests.http_post("https://example.com", data="not a dict")

def test_http_get_retries_on_failure(requests_mock):
    url = "https://example.com/retry"
    requests_mock.get(url, )

    with pytest.raises(Exception):  # requests.HTTPError or general depending on StaticMethods.attempt
        StaticMethods.Requests.http_get(url, retries=2)

    assert requests_mock.call_count == 2  # total attempts, not retries + 1

def test_http_post_retries_on_failure(requests_mock):
    url = "https://example.com/fail"
    payload = {"x": 1}
    requests_mock.post(url, status_code=502)

    with pytest.raises(Exception):
        StaticMethods.Requests.http_post(url, data=payload, retries=2)

    assert requests_mock.call_count == 2  # total attempts (NOT 2 + 1)