import shutil
from typing import Iterator
import pytest
import os
import requests
from mileslib import StaticMethods as sm
from pathlib import Path
from test_logger import Logger
from datetime import datetime

### Static Methods ###

### Script ###

class Main:
    def __init__(self, pdir = None):
        '''
        Parent instance of Requests.
        :param pdir: Project directory, usually os.getcwd(), unless specified by config files.
        '''
        pdir = pdir or os.getcwd()
        self.pdir = sm.validate_instance_directory(pdir=pdir)
        self.launch_time = datetime.utcnow()
        self.logger = Logger(inst=self)

class Requests:
    def __init__(self, inst):
        """
        Generic class that operates on a passed-in RenderTestBoilerplate instance.
        :param inst Argument for instance passed through the class.
        """
        sm.validate_instance(inst=inst)
        self.m = inst
        self.pdir = self.m.pdir
        self.logger = self.m.logger

        # Directory Initialization
        self.requests_dir = self.pdir / "Requests"
        sm.validate_directory(self.requests_dir)

        #ID
        self._id = self.pdir.name

        #Contents
        self.contents = list(self.requests_dir.iterdir())  # ← FIXED LINE

    @sm.timer(label="http_get")
    def http_get(self, url: str, retries: int = 3) -> requests.Response:
        sm.check_input(url, str, "url")
        sm.check_input(retries, int, "retries")
        self.logger.info("Starting GET request", url=url)

        # define the single‐try function
        def _do_get():
            resp = requests.get(url)
            resp.raise_for_status()
            return resp

        # delegate retry logic
        return sm.attempt(_do_get, retries=retries)

    @sm.timer(label="http_post")
    def http_post(self, url: str, data: dict, retries: int = 3) -> requests.Response:
        sm.check_input(url, str, "url")
        sm.check_input(data, dict, "data")
        sm.check_input(retries, int, "retries")
        self.logger.info("Starting POST request", url=url, payload=data)

        def _do_post():
            resp = requests.post(url, json=data)
            resp.raise_for_status()
            return resp

        return sm.attempt(_do_post, retries=retries)

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
        self.contents = list(self.requests_dir.iterdir())

    def is_empty(self) -> bool:
        return not self.contents

    def snapshot(self, target_dir: Path):
        shutil.copytree(self.requests_dir, target_dir)

    def to_dict(self) -> dict:
        return {
            "path": str(self.requests_dir),
            "id": self._id,
            "items": [f.name for f in self.contents]
        }

    def copy_to(self, dest_dir: Path):
        sm.validate_directory(dest_dir)
        for f in self.requests_dir.iterdir():
            shutil.copy2(f, dest_dir / f.name)

    ### Requests Methods ###
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
    def verify_or_create_file(file_path: Path, label: str = "file") -> Path:
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
        return f"<{self.__class__.__name__} path='{self.requests_dir}'>"

    def __str__(self) -> str:
        """
        Return a human-readable string describing the object.

        Example:
            Boilerplate at '/home/user/project' with 5 items
        """
        return f"{self.__class__.__name__} at '{self.requests_dir}' with {len(self)} items"

    def __bool__(self) -> bool:
        """
        Return True if the backing directory exists and is valid.

        Enables:
            if obj: ...
        """
        return self.requests_dir.exists() and self.requests_dir.is_dir()

    def __eq__(self, other: object) -> bool:
        """
        Check if two Requests instances point to the same directory.

        Returns:
            bool: True if same type and same path.
        """
        return isinstance(other, Requests) and self.requests_dir == other.requests_dir

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
        return hash(self.requests_dir)

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
def class_instance(main_instance: Main) -> Requests:
    """A Requests instance created from a valid Main."""
    return Requests(inst=main_instance)


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


# ─── Initialization & Directory Tests for Requests ────────────────────────

class TestRequestsInitialization:
    def test_requires_valid_instance(self, tmp_dir):
        # anything without __dict__ should fail validation
        with pytest.raises(RuntimeError):
            Requests(inst="not_a_Main")

    def test_class_dir_is_created(self, main_instance, tmp_dir):
        _ = Requests(inst=main_instance)  # Instantiation creates the directory
        class_dir = tmp_dir / "Requests"
        assert class_dir.exists() and class_dir.is_dir()


# ─── Magic‐Method & Sequence‐Behavior Tests for Requests ────────────────────

class TestRequestsMagicMethods:
    def test_repr_shows_class_name_and_path(self, class_instance):
        expected = f"<Requests path='{class_instance.requests_dir}'>"
        assert repr(class_instance) == expected

    def test_str_includes_item_count(self, class_instance):
        s = str(class_instance)
        assert class_instance.requests_dir.name in s
        assert f"with {len(class_instance)} items" in s

    def test_bool_reflects_directory_existence(self, class_instance, tmp_dir):
        assert bool(class_instance) is True

        # remove folder → __bool__ should now be False
        inst = Requests(inst=Main(pdir=tmp_dir))
        inst.requests_dir.rmdir()
        assert not bool(inst)

    def test_equality_on_same_and_different_paths(self, tmp_dir):
        # same path → equal
        m1 = Main(pdir=tmp_dir)
        m2 = Main(pdir=tmp_dir)
        c1 = Requests(inst=m1)
        c2 = Requests(inst=m2)
        assert c1 == c2
        assert not (c1 != c2)

        # different paths → not equal
        d1 = tmp_dir / "a"; d2 = tmp_dir / "b"
        d1.mkdir(); d2.mkdir()
        c3 = Requests(inst=Main(pdir=d1))
        c4 = Requests(inst=Main(pdir=d2))
        assert c3 != c4

    def test_len_contains_getitem_iter_and_refresh(self, class_instance):
        # start empty
        initial = len(class_instance)
        assert initial == 0

        # add files
        for name in ("a.txt", "b.txt"):
            (class_instance.requests_dir / name).write_text("x")
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


# ─── API‐Method Tests for Requests ──────────────────────────────────────────

class TestRequestsMethods:
    def test_dynamic_method_echoes_argument(self, class_instance):
        for val in ("hi", 123, None):
            assert class_instance.dynamic_method(val) == val

    def test_class_method_returns_class_name(self):
        assert Requests.class_method() == "Requests"

    def test_static_method_passthrough(self):
        for val in ("xyz", 3.14, [1, 2, 3]):
            assert Requests.static_method(val) == val

    def test_dynamic_method_handles_exceptions_gracefully(self, class_instance):
        def failing_func(x): raise ValueError("intentional")

        with pytest.raises(ValueError):
            _ = class_instance.dynamic_method(failing_func("fail"))

# --- HTTPS Tests
class DummyResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.content = b'ok'
    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"Status code: {self.status_code}")

class TestHTTPS:
    def test_http_get_success(self, monkeypatch, class_instance):
        dummy = DummyResponse(200)
        calls = []
        def fake_get(url):
            calls.append(url)
            return dummy
        monkeypatch.setattr(requests, 'get', fake_get)

        resp = class_instance.http_get('http://example.com', retries=3)
        assert resp is dummy
        assert calls == ['http://example.com']

    def test_http_get_http_error_retries(self, monkeypatch, class_instance):
        """Simulate HTTP errors and ensure HTTPError is raised after retries."""
        def fake_get(url):
            return DummyResponse(500)
        monkeypatch.setattr(requests, 'get', fake_get)

        with pytest.raises(requests.HTTPError):
            class_instance.http_get('http://error.com', retries=2)

    def test_http_get_type_error(self, class_instance):
        """Invalid URL type should raise TypeError from check_input."""
        with pytest.raises(TypeError):
            class_instance.http_get(123, retries=3)


    def test_http_post_success(self, monkeypatch, class_instance):
        dummy = DummyResponse(201)
        calls = []
        def fake_post(url, json):
            calls.append((url, json))
            return dummy
        monkeypatch.setattr(requests, 'post', fake_post)

        resp = class_instance.http_post('http://example.com', {'a': 1}, retries=2)
        assert resp is dummy
        assert calls == [('http://example.com', {'a': 1})]

    def test_http_post_type_error(self, class_instance):
        """Invalid data type should raise TypeError from check_input."""
        with pytest.raises(TypeError):
            class_instance.http_post('http://example.com', 'not a dict', retries=3)

# ─── File Handling Tests for Requests ──────────────────────────────────────────

class TestRequestsFileHandling:

    def test_creates_new_file(self, class_instance):
        """Test that a missing file is created by verify_or_create_file."""
        file_path = class_instance.requests_dir / "created_file.txt"

        result = class_instance.verify_or_create_file(file_path, label="test file")

        assert result.exists()
        assert result.is_file()
        assert result == file_path


    def test_returns_existing_file(self, class_instance):
        """Test that an existing file is returned without error."""
        file_path = class_instance.requests_dir / "existing_file.txt"
        file_path.write_text("preexisting")

        result = class_instance.verify_or_create_file(file_path, label="test file")

        assert result == file_path
        assert result.read_text() == "preexisting"


    def test_fails_gracefully_when_file_cannot_be_created(self, monkeypatch, class_instance):
        """Simulate sm.exists() throwing and file not being created."""
        def mock_exists(path, create_if_missing=True):
            raise FileNotFoundError("simulated failure")

        monkeypatch.setattr(sm, "exists", mock_exists)

        file_path = class_instance.requests_dir / "fail.txt"

        with pytest.raises(RuntimeError) as excinfo:
            Requests.verify_or_create_file(file_path, label="broken")

        assert "could not create broken" in str(excinfo.value)


    def test_returns_none_if_file_exists_after_failure(self, monkeypatch, class_instance):
        file_path = class_instance.requests_dir / "race_condition.txt"
        file_path.touch()

        def mock_exists(path, create_if_missing=True):
            raise FileNotFoundError("simulated flaky condition")

        monkeypatch.setattr(sm, "exists", mock_exists)

        result = Requests.verify_or_create_file(file_path, label="fallback")
        assert result.exists()
        assert result == file_path

    def test_refresh_resets_contents(self, class_instance):
        assert len(class_instance) == 0
        (class_instance.requests_dir / "new.txt").write_text("test")
        class_instance.refresh()
        assert "new.txt" in class_instance

    def test_write_and_read_file(self, class_instance):
        test_file = class_instance.requests_dir / "sample.txt"
        test_file.write_text("hello world")
        assert test_file.exists()
        assert test_file.read_text() == "hello world"

    def test_snapshot_creates_copy(self, tmp_path, class_instance):
        (class_instance.requests_dir / "x.txt").write_text("data")
        target = tmp_path / "clone"
        class_instance.snapshot(target)
        assert (target / "x.txt").exists()

    def test_copy_to_creates_duplicates(self, tmp_path, class_instance):
        (class_instance.requests_dir / "a.txt").write_text("x")
        new_dir = tmp_path / "dest"
        class_instance.copy_to(new_dir)
        assert (new_dir / "a.txt").exists()

# ─── Misc Handling Tests for Requests ──────────────────────────────────────────

class TestRequestsMisc:

    def test_to_dict_has_keys(self, class_instance):
        d = class_instance.to_dict()
        assert "path" in d and "id" in d and "items" in d