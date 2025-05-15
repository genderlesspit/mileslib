from typing import Iterator
import pytest
import os
from staticmethods import StaticMethods as sm
from pathlib import Path

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
    - Automatically installs if missing (dev-safe, not production-safe).

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

### Script ###

class test_Main:
    def __init__(self, pdir = None):
        '''
        Parent instance of Github.
        :param pdir: Project directory, usually os.getcwd(), unless specified by config files.
        '''
        pdir = pdir or os.getcwd()
        self.pdir = sm.validate_instance_directory(pdir=pdir)

class Github:
    def __init__(self, inst):
        """
        Github operates on a passed-in test_Main instance.
        :param inst Argument for instance passed through the classname.
        """
        sm.validate_instance(inst=inst)
        self.m = inst
        self.pdir = self.m.pdir

        # Directory Initialization
        self.class_dir = self.pdir / "Github"
        sm.validate_directory(self.class_dir)

        #ID
        self._id = self.pdir.name

        #Contents
        self.contents = list(self.pdir.iterdir())

    ### Dynamic Methods ###
    def dynamic_method(self, arg):
        """
        Placeholder dynamic method.
        - Uses instance state (`self`)
        """
        return arg

    ### Github Methods ###
    @classmethod
    def class_method(cls):
        """
        Placeholder classname method.
        - Uses classname reference (`cls`)
        """
        return cls.__name__

    ### Static Methods ###
    @staticmethod
    def static_method(arg):
        """
        Placeholder static method.
        - Stateless; does not use `self` or `cls`
        """
        return arg

    def __repr__(self) -> str:
        """
        Return the official representation of the object for debugging.

        Example:
            <Boilerplate path='/home/user/project'>
        """
        return f"<{self.__class__.__name__} path='{self.class_dir}'>"

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
        Check if two Github instances point to the same directory.

        Returns:
            bool: True if same type and same path.
        """
        return isinstance(other, Github) and self.class_dir == other.class_dir

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

@pytest.fixture
def temp_Github(tmp_path):
    """Creates a Github instance with a temporary directory."""
    main = test_Main(pdir=tmp_path)
    instance = Github(inst=main)
    return instance

def test_repr_returns_expected_string(temp_Github):
    result = repr(temp_Github)
    assert result.startswith("<Github path='")
    assert str(temp_Github.class_dir) in result

def test_str_returns_human_readable(temp_Github):
    expected_prefix = f"Github at '{temp_Github.class_dir}' with"
    assert str(temp_Github).startswith(expected_prefix)

def test_bool_true_when_valid_dir(temp_Github):
    assert bool(temp_Github) is True

def test_bool_false_when_path_deleted(tmp_path):
    main = test_Main(pdir=tmp_path)
    instance = Github(inst=main)
    instance.class_dir.rmdir()
    assert bool(instance) is False

def test_eq_same_path_same_object(tmp_path):
    main1 = test_Main(pdir=tmp_path)
    main2 = test_Main(pdir=tmp_path)
    c1 = Github(inst=main1)
    c2 = Github(inst=main2)
    assert c1 == c2


def test_eq_different_path_objects(tmp_path):
    path_a = tmp_path / "a"
    path_b = tmp_path / "b"
    path_a.mkdir()
    path_b.mkdir()

    main1 = test_Main(pdir=path_a)
    main2 = test_Main(pdir=path_b)
    c1 = Github(inst=main1)
    c2 = Github(inst=main2)

    assert c1 != c2

def test_len_counts_files_correctly(temp_Github):
    temp_Github.refresh()  # Ensure accurate baseline
    initial_count = len(temp_Github)

    (temp_Github.class_dir / "file1.txt").write_text("A")
    (temp_Github.class_dir / "file2.txt").write_text("B")
    temp_Github.refresh()

    expected = initial_count + 2
    assert len(temp_Github) == expected

def test_contains_checks_file_by_name(temp_Github):
    (temp_Github.class_dir / "testfile.txt").write_text("data")
    temp_Github.refresh()
    assert "testfile.txt" in temp_Github
    assert "nonexistent.txt" not in temp_Github

def test_getitem_returns_path_by_index(temp_Github):
    file1 = temp_Github.class_dir / "file1.txt"
    file2 = temp_Github.class_dir / "file2.txt"
    file1.write_text("one")
    file2.write_text("two")
    temp_Github.refresh()
    assert temp_Github[0].name in {"file1.txt", "file2.txt"}
    assert isinstance(temp_Github[0], Path)

def test_iter_yields_all_contents(temp_Github):
    files = ["a.txt", "b.txt", "c.txt"]
    for name in files:
        (temp_Github.class_dir / name).write_text("data")
    temp_Github.refresh()
    names = [f.name for f in temp_Github]
    for name in files:
        assert name in names

def test_refresh_updates_internal_file_list(temp_Github):
    temp_Github.refresh()  # Ensure contents is accurate
    initial_count = len(temp_Github)

    new_file = temp_Github.class_dir / "new.txt"
    new_file.write_text("added later")

    temp_Github.refresh()
    assert len(temp_Github) == initial_count + 1
    assert "new.txt" in temp_Github

### Tests for Method ###

def test_dynamic_method_returns_argument(temp_Github):
    """Ensure dynamic_method echoes the input value using instance."""
    assert temp_Github.dynamic_method("value") == "value"
    assert temp_Github.dynamic_method(123) == 123


def test_class_method_returns_class_name():
    """Ensure class_method returns the name of the classname as a string."""
    result = Github.class_method()
    assert isinstance(result, str)
    assert result == "Github"


def test_static_method_returns_argument():
    """Ensure static_method echoes the input value."""
    assert Github.static_method("static") == "static"
    assert Github.static_method(42) == 42