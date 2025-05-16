import shutil
from typing import Iterator
import logging
from pathlib import Path
import sys
import pytest
from unittest import mock
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime
from mileslib import StaticMethods as sm

### Static Methods ###
"""
StaticMethods Utility Module
============================

This internal utility classname (`StaticMethods`) provides static helper methods used throughout
MilesLib components to enforce type validation, file/directory sanity, instance hygiene,
dependency checking, retry logic, and logging-safe operations.

It is intended as a reusable drop-in for backend classes that need consistent, testable
validation and runtime behavior without requiring stateful inheritance.

Methods Overview
----------------

1. check_input(arg, expected, label):
    - Raises TypeError if `arg` is not of the expected type(s).
    - Ideal for validating arguments in public methods.

2. restart(self):
    - Forcefully restarts the running Python process.
    - Use only for CLI scripts or daemon-style workers.

3. exists(path, disp, quiet, create_if_missing):
    - Checks for file or directory existence.
    - Optionally creates missing paths if requested.
    - Logs outcome unless `quiet` is True.

4. dependency(dep, pack):
    - Ensures a pip dependency is installed.
    - Automatically installs if missing (.dev-safe, not production-safe).

5. timer(fn, *args, **kwargs):
    - Times execution duration of a function call.
    - Returns both result and duration.

6. recall(fn, max_attempts, handled_exceptions):
    - Retries a function multiple times on failure.
    - Raises the last exception after exhausting retries.
    - Useful for unstable I/O or API endpoints.

7. traverse_dictionary(data, *keys, default):
    - Traverses nested dictionaries/lists safely.
    - Supports mixed key/index access with graceful fallback.

8. validate_instance(inst):
    - Ensures an object is not None and is classname-like.
    - Rejects primitives and empty placeholders.

9. validate_instance_directory(pdir):
    - Ensures `.pdir` on an instance is a valid existing Path.
    - Accepts str or Path.

10. validate_directory(path):
    - Ensures a directory exists; creates it if not.
    - Raises if path exists but is not a directory.

11. validate_file(path):
    - Ensures a file exists.
    - Raises if missing or if the path is a directory.

12. ensure_file_with_default(path, default, encoding):
    - Creates a file if missing or empty and writes a default (str or JSON).
    - Raises if the default is not string-like or dict.

Usage Pattern
-------------
In consuming classes like `Config`, `Logger`, `TaskRunner`, etc., methods from this classname
should be accessed via dependency injection like:

    classname Config:
        def __init__(self, inst):
            self.m = inst
            self.sm = inst.sm

        def load(self):
            self.sm.check_input(self.path, str, label="Config path")
            ...

You should **never instantiate StaticMethods** — it is purely a namespace for reusable logic.

"""

class Main:
    def __init__(self, pdir: Path = os.getcwd()):
        self.sm = sm
        self.pdir = sm.validate_instance_directory(pdir)
        self.launch_time = datetime.utcnow()

class Logger:
    def __init__(self, inst):
        """
        Logger operates on a passed-in test_Main instance.
        :param inst Argument for instance passed through the classname.
        """
        sm.validate_instance(inst=inst)
        self.m = inst
        self.pdir = self.m.pdir
        self.log_stamp = self.m.launch_time.strftime("%Y-%m-%d_%H-%M-%S")

        self.log_dir = sm.validate_directory(self.m.pdir / "logs")
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
            log_file_dir , was_log_file_created = sm.exists(path=Path(self.log_dir / f"{self.log_stamp}.log"),create_if_missing=True)
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
            sm.dependency("structlog")
            try:
                structlog = sm.recall(import_structlog, max_attempts=3, handled_exceptions=(ImportError,))
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

### Fixtures ###

"""
Default Fixtures Overview
=========================

These fixtures are used across multiple unit tests to simulate edge cases,
provide generic inputs, and validate error handling across modules like Config,
Logger, and other MilesLib components.

Each fixture returns a specific object or value type for TDD-oriented testing.

Fixtures
--------

1. broken_directory:
    - Simulates a syntactically invalid directory string.
    - Used to test path validation and error handling in init routines.

2. broken_main_directory:
    - Returns an instance with a broken pdir attribute set to a corrupt path.
    - Triggers FileNotFoundError or path-based logic errors during instantiation.

3. sample_string:
    - A basic lowercase string for text-based logic and transformations.
    - Useful for testing string methods, formatting, or casing.

4. sample_object:
    - Dummy classname with a single `.value = 42` attribute.
    - Used to test generic object attribute access or mocking.

5. sample_tuple:
    - Tuple of (int, str, float): `(1, "two", 3.0)`.
    - Useful for unpacking, type validation, or multi-type logic testing.

6. missing_file_path:
    - A `Path` object pointing to a guaranteed missing file in a temp directory.
    - Use to test FileNotFoundError, fallback logic, or safe file access.

7. broken_instance:
    - Object that raises `AttributeError` for any accessed attribute.
    - Validates code paths that assume attribute presence or introspection.

8. numeric_values:
    - Includes edge-case numbers: `0`, `-1`, `1`, `3.14`, `inf`, `-inf`, `nan`.
    - Useful for range checking, float safety, and math edge case handling.

9. falsy_values:
    - Includes Python's core falsy values: `None`, `False`, `0`, `""`, `[]`, `{}`, `set()`.
    - Helps verify truthiness assumptions and guard logic.

10. non_string_keys:
    - Returns non-str types commonly used incorrectly as dict keys:
      `int`, `None`, `bool`, `float`, `tuple`, `object`.
    - Tests dict key validation or serialization constraints.
"""

### Custom Tests ###

def test_structlog_auto_install_fails(temp_log_file):
    original_import = __import__
    def failing_import(name, *args, **kwargs):
        if name == "structlog":
            raise ImportError("No structlog")
        return original_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=failing_import):
        with mock.patch("test_logger.sm.dependency") as mock_dep:
            with pytest.raises(RuntimeError, match="structlog could not be properly loaded"):
                from test_logger import Logger
                Logger.setup_structlog_logger(temp_log_file)

            mock_dep.assert_called_once_with("structlog")

def test_structlog_auto_install_succeeds(temp_log_file):
    sys.modules.pop("test_logger", None)

    # SAVE the true built-in __import__ BEFORE mocking begins
    real_import = __import__

    with mock.patch.dict("sys.modules", {"structlog": None}):
        with mock.patch("builtins.__import__") as mock_import:
            def fake_import(name, *args, **kwargs):
                if name == "structlog":
                    mock_structlog = mock.MagicMock()

                    # required structlog methods & fields
                    mock_structlog.get_logger.return_value = mock.MagicMock()
                    mock_structlog.configure.return_value = None
                    mock_structlog.stdlib = mock.MagicMock()
                    mock_structlog.stdlib.LoggerFactory.return_value = mock.MagicMock()
                    mock_structlog.make_filtering_bound_logger.return_value = mock.MagicMock()

                    # processors
                    mock_structlog.processors = mock.MagicMock()
                    mock_structlog.processors.TimeStamper.return_value = lambda logger, method, event_dict: event_dict
                    mock_structlog.processors.JSONRenderer.return_value = lambda logger, method, event_dict: event_dict

                    mock_import.side_effect = None  # remove side effect after simulating success
                    return mock_structlog

                return real_import(name, *args, **kwargs)

def test_logger_writes_json_logs_to_file(temp_logger):
    logger = temp_logger
    test_event = "test_event"
    logger.info(test_event, user="tester", value=123)

    # Use the logger's known file
    log_file = logger.log_file_dir

    for handler in logging.getLogger().handlers:
        handler.flush()
        handler.close()

    assert log_file.exists(), "Log file was not created."
    log_lines = log_file.read_text().strip().splitlines()
    assert len(log_lines) >= 1, "No log lines found in the log file."

def test_logger_console_output(capfd, temp_logger):
    logger = temp_logger
    test_event = "console_test_event"
    logger.info(test_event, extra_info="console")

    sys.stderr.flush()  # flush stderr

    captured = capfd.readouterr().err.strip().splitlines()
    assert any(test_event in line for line in captured), "Event not found in console stderr output."

def test_log_rotation(temp_logger):
    """Test that log rotation works by writing enough log events to exceed the threshold."""
    logger = temp_logger
    log_file = logger.log_file_dir  # <-- actual log file path
    log_dir = log_file.parent

    # Write multiple small log entries to force rotation
    for i in range(1000):
        logger.info("rotation_test", entry=i, payload="x" * 1000)

    # Flush and close handlers
    for handler in logging.getLogger().handlers:
        try:
            handler.flush()
            handler.close()
        except ValueError:
            pass  # Already closed

    # Check for rotated files
    rotated_logs = list(log_dir.glob(f"{log_file.name}*"))
    assert len(rotated_logs) > 1, "Log rotation did not create backup files."

### Default Tests/Fixtures ###

@pytest.fixture
def temp_logger(tmp_path):
    """Creates a Logger instance with a temporary directory."""
    main = Main(pdir=tmp_path)
    instance = Logger(inst=main)
    return instance

@pytest.fixture
def temp_log_file(tmp_path: Path):
    """Provide a temporary log file path."""
    return tmp_path / "logs" / "app.log"

### Special Method Tests ###

def test_repr_returns_expected_format(temp_logger):
    result = repr(temp_logger)
    assert result.startswith("<Logger id=")
    assert str(temp_logger.log_dir) in result
    assert temp_logger.log_file_dir.name in result

def test_str_returns_human_readable_string(temp_logger):
    result = str(temp_logger)
    assert result.startswith(f"Logger at '{temp_logger.class_dir}' with")

def test_bool_true_if_class_dir_exists(temp_logger):
    assert bool(temp_logger) is True

def test_bool_false_if_class_dir_missing(tmp_path):
    main = Main(pdir=tmp_path)
    logger = Logger(inst=main)

    # Close file handles to allow deletion (important on Windows)
    logger.close_handlers()

    # Now forcibly delete the logger's directory
    shutil.rmtree(logger.class_dir)

    # Should now return False
    assert bool(logger) is False


def test_eq_returns_true_for_same_path(tmp_path):
    main1 = Main(pdir=tmp_path)
    main2 = Main(pdir=tmp_path)
    l1 = Logger(inst=main1)
    l2 = Logger(inst=main2)
    assert l1 == l2

def test_eq_returns_false_for_different_dirs(tmp_path):
    p1 = tmp_path / "one"
    p2 = tmp_path / "two"
    p1.mkdir()
    p2.mkdir()
    l1 = Logger(inst=Main(p1))
    l2 = Logger(inst=Main(p2))
    assert l1 != l2

def test_len_matches_class_dir_file_count(temp_logger):
    # Add 2 files
    (temp_logger.class_dir / "logA.txt").write_text("a")
    (temp_logger.class_dir / "logB.txt").write_text("b")
    temp_logger.refresh()
    assert len(temp_logger) >= 2

def test_contains_checks_by_filename(temp_logger):
    filename = "included.txt"
    (temp_logger.class_dir / filename).write_text("yes")
    temp_logger.refresh()
    assert filename in temp_logger
    assert "not_here.txt" not in temp_logger

def test_getitem_returns_correct_path_type(temp_logger):
    (temp_logger.class_dir / "one.log").write_text("x")
    (temp_logger.class_dir / "two.log").write_text("y")
    temp_logger.refresh()
    path = temp_logger[0]
    assert isinstance(path, Path)
    assert path.exists()

def test_iterates_all_files(temp_logger):
    expected = {"a.txt", "b.txt", "c.txt"}
    for name in expected:
        (temp_logger.class_dir / name).write_text("log")
    temp_logger.refresh()
    found = {p.name for p in temp_logger}
    assert expected.issubset(found)

def test_refresh_updates_contents(temp_logger):
    before = len(temp_logger)
    (temp_logger.class_dir / "x").write_text("1")
    temp_logger.refresh()
    assert len(temp_logger) == before + 1

### Logger Behavior ###

def test_dynamic_method_passthrough(temp_logger):
    assert temp_logger.dynamic_method("hi") == "hi"
    assert temp_logger.dynamic_method(123) == 123

def test_class_method_is_logger_name():
    assert Logger.class_method() == "Logger"