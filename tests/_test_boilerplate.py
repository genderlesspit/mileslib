import shutil
from typing import Iterator
import pytest
import os
from staticmethods import StaticMethods as sm
from pathlib import Path

### Static Methods ###
"""
StaticMethods Utility Module
============================

This internal utility class (`StaticMethods`) provides static helper methods used throughout
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
    - Ensures an object is not None and is class-like.
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
In consuming classes like `Config`, `Logger`, `TaskRunner`, etc., methods from this class
should be accessed via dependency injection like:

    class Config:
        def __init__(self, inst):
            self.m = inst
            self.sm = inst.sm

        def load(self):
            self.sm.check_input(self.path, str, label="Config path")
            ...

You should **never instantiate StaticMethods** — it is purely a namespace for reusable logic.

"""

### Script ###

class Main:
    def __init__(self, pdir = None):
        '''
        Parent instance of Class.
        :param pdir: Project directory, usually os.getcwd(), unless specified by config files.
        '''
        pdir = pdir or os.getcwd()
        self.pdir = sm.validate_instance_directory(pdir=pdir)

class Class:
    def __init__(self, inst):
        """
        Generic class that operates on a passed-in RenderTestBoilerplate instance.
        :param inst Argument for instance passed through the class.
        """
        sm.validate_instance(inst=inst)
        self.m = inst
        self.pdir = self.m.pdir

        # Directory Initialization
        self.class_dir = self.pdir / "Class"
        sm.validate_directory(self.class_dir)

        #ID
        self._id = self.pdir.name

        #Contents
        self.contents = list(self.class_dir.iterdir())  # ← FIXED LINE

    ### Dynamic Methods ###
    def dynamic_method(self, arg):
        """
        Placeholder dynamic method.
        - Uses instance state (`self`)
        """
        return arg

    def refresh(self) -> None:
        """
        Reload the contents from disk.
        Use after files have changed outside the object context.
        """
        self.contents = list(self.class_dir.iterdir())

    def is_empty(self) -> bool:
        return not self.contents

    def snapshot(self, target_dir: Path):
        shutil.copytree(self.class_dir, target_dir)

    def to_dict(self) -> dict:
        return {
            "path": str(self.class_dir),
            "id": self._id,
            "items": [f.name for f in self.contents]
        }

    def copy_to(self, dest_dir: Path):
        sm.validate_directory(dest_dir)
        for f in self.class_dir.iterdir():
            shutil.copy2(f, dest_dir / f.name)

    ### Class Methods ###
    @classmethod
    def from_dict(cls, inst, data: dict):
        obj = cls(inst)
        obj._id = data.get("id", "")
        return obj

    @classmethod
    def class_method(cls):
        """
        Placeholder class method.
        - Uses class reference (`cls`)
        """
        return cls.__name__

    ### Static Methods ###
    @staticmethod
    def verify_or_create_file(self, file_path: Path, label: str = "file") -> Path:
        """
        Verifies that a file exists at `file_path`, optionally creates it.
        Returns the file path even if sm.exists fails, as long as the file exists.
        """
        try:
            verified_path, was_file_created = sm.exists(path=file_path, create_if_missing=True)
            return Path(verified_path)
        except Exception as e:
            if file_path.exists():
                return file_path  # fallback: file is there, ignore sm.exists error
            raise RuntimeError(f"sm.exists() is broken — could not create {label}: {e}")

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
        Check if two Class instances point to the same directory.

        Returns:
            bool: True if same type and same path.
        """
        return isinstance(other, Class) and self.class_dir == other.class_dir

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

    def __hash__(self):
        return hash(self.class_dir)

    def __json__(self):
        return self.to_dict()

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
    - Dummy class with a single `.value = 42` attribute.
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

# ─── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """A clean temporary project directory."""
    return tmp_path

@pytest.fixture
def main_instance(tmp_dir: Path) -> Main:
    """A Main instance rooted at an empty tmp_dir."""
    return Main(pdir=tmp_dir)

@pytest.fixture
def class_instance(main_instance: Main) -> Class:
    """A Class instance created from a valid Main."""
    return Class(inst=main_instance)


# ─── Tests for Main ─────────────────────────────────────────────────────

class TestMain:
    def test_default_pdir_is_set_correctly(self, tmp_dir):
        m = Main(pdir=tmp_dir)
        assert isinstance(m.pdir, Path)
        assert m.pdir == tmp_dir

    def test_main_raises_file_not_found_for_invalid_dir(self, tmp_path):
        bad = tmp_path / "does_not_exist"
        with pytest.raises(FileNotFoundError):
            Main(pdir=bad)


# ─── Initialization & Directory Tests for Class ────────────────────────

class TestClassInitialization:
    def test_requires_valid_instance(self, tmp_dir):
        # anything without __dict__ should fail validation
        with pytest.raises(RuntimeError):
            Class(inst="not_a_Main")

    def test_class_dir_is_created(self, main_instance, tmp_dir):
        _ = Class(inst=main_instance)  # Instantiation creates the directory
        class_dir = tmp_dir / "Class"
        assert class_dir.exists() and class_dir.is_dir()


# ─── Magic‐Method & Sequence‐Behavior Tests for Class ────────────────────

class TestClassMagicMethods:
    def test_repr_shows_class_name_and_path(self, class_instance):
        expected = f"<Class path='{class_instance.class_dir}'>"
        assert repr(class_instance) == expected

    def test_str_includes_item_count(self, class_instance):
        s = str(class_instance)
        assert class_instance.class_dir.name in s
        assert f"with {len(class_instance)} items" in s

    def test_bool_reflects_directory_existence(self, class_instance, tmp_dir):
        assert bool(class_instance) is True

        # remove folder → __bool__ should now be False
        inst = Class(inst=Main(pdir=tmp_dir))
        inst.class_dir.rmdir()
        assert not bool(inst)

    def test_equality_on_same_and_different_paths(self, tmp_dir):
        # same path → equal
        m1 = Main(pdir=tmp_dir)
        m2 = Main(pdir=tmp_dir)
        c1 = Class(inst=m1)
        c2 = Class(inst=m2)
        assert c1 == c2
        assert not (c1 != c2)

        # different paths → not equal
        d1 = tmp_dir / "a"; d2 = tmp_dir / "b"
        d1.mkdir(); d2.mkdir()
        c3 = Class(inst=Main(pdir=d1))
        c4 = Class(inst=Main(pdir=d2))
        assert c3 != c4

    def test_len_contains_getitem_iter_and_refresh(self, class_instance):
        # start empty
        initial = len(class_instance)
        assert initial == 0

        # add files
        for name in ("a.txt", "b.txt"):
            (class_instance.class_dir / name).write_text("x")
        class_instance.refresh()

        # length updated
        assert len(class_instance) == initial + 2

        # __contains__
        assert "a.txt" in class_instance
        assert "missing.txt" not in class_instance

        # __getitem__ and IndexError
        assert (class_instance[0].name in {"a.txt", "b.txt"})
        with pytest.raises(IndexError):
            _ = class_instance[999]

        # __iter__
        names = sorted(p.name for p in class_instance)
        assert names == sorted(["a.txt", "b.txt"])


# ─── API‐Method Tests for Class ──────────────────────────────────────────

class TestClassMethods:
    def test_dynamic_method_echoes_argument(self, class_instance):
        for val in ("hi", 123, None):
            assert class_instance.dynamic_method(val) == val

    def test_class_method_returns_class_name(self):
        assert Class.class_method() == "Class"

    def test_static_method_passthrough(self):
        for val in ("xyz", 3.14, [1, 2, 3]):
            assert Class.static_method(val) == val

    def test_dynamic_method_handles_exceptions_gracefully(self, class_instance):
        def failing_func(x): raise ValueError("intentional")

        with pytest.raises(ValueError):
            _ = class_instance.dynamic_method(failing_func("fail"))

# ─── File Handling Tests for Class ──────────────────────────────────────────

class TestClassFileHandling:

    def test_creates_new_file(self, class_instance):
        """Test that a missing file is created by verify_or_create_file."""
        file_path = class_instance.class_dir / "created_file.txt"

        result = class_instance.verify_or_create_file(class_instance, file_path, label="test file")

        assert result.exists()
        assert result.is_file()
        assert result == file_path


    def test_returns_existing_file(self, class_instance):
        """Test that an existing file is returned without error."""
        file_path = class_instance.class_dir / "existing_file.txt"
        file_path.write_text("preexisting")

        result = class_instance.verify_or_create_file(class_instance, file_path, label="test file")

        assert result == file_path
        assert result.read_text() == "preexisting"


    def test_fails_gracefully_when_file_cannot_be_created(self, monkeypatch, class_instance):
        """Simulate sm.exists() throwing and file not being created."""
        def mock_exists(path, create_if_missing=True):
            raise FileNotFoundError("simulated failure")

        monkeypatch.setattr(sm, "exists", mock_exists)

        file_path = class_instance.class_dir / "fail.txt"

        with pytest.raises(RuntimeError) as excinfo:
            Class.verify_or_create_file(class_instance, file_path, label="broken")

        assert "could not create broken" in str(excinfo.value)


    def test_returns_none_if_file_exists_after_failure(self, monkeypatch, class_instance):
        file_path = class_instance.class_dir / "race_condition.txt"
        file_path.touch()

        def mock_exists(path, create_if_missing=True):
            raise FileNotFoundError("simulated flaky condition")

        monkeypatch.setattr(sm, "exists", mock_exists)

        result = Class.verify_or_create_file(class_instance, file_path, label="fallback")
        assert result.exists()
        assert result == file_path

    def test_refresh_resets_contents(self, class_instance):
        assert len(class_instance) == 0
        (class_instance.class_dir / "new.txt").write_text("test")
        class_instance.refresh()
        assert "new.txt" in class_instance

    def test_write_and_read_file(self, class_instance):
        test_file = class_instance.class_dir / "sample.txt"
        test_file.write_text("hello world")
        assert test_file.exists()
        assert test_file.read_text() == "hello world"

    def test_snapshot_creates_copy(self, tmp_path, class_instance):
        (class_instance.class_dir / "x.txt").write_text("data")
        target = tmp_path / "clone"
        class_instance.snapshot(target)
        assert (target / "x.txt").exists()

    def test_copy_to_creates_duplicates(self, tmp_path, class_instance):
        (class_instance.class_dir / "a.txt").write_text("x")
        new_dir = tmp_path / "dest"
        class_instance.copy_to(new_dir)
        assert (new_dir / "a.txt").exists()

# ─── Misc Handling Tests for Class ──────────────────────────────────────────

class TestClassMisc:

    def test_to_dict_has_keys(self, class_instance):
        d = class_instance.to_dict()
        assert "path" in d and "id" in d and "items" in d
