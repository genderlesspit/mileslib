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
        Parent instance of Requests.
        :param pdir: Project directory, usually os.getcwd(), unless specified by config files.
        '''
        pdir = pdir or os.getcwd()
        self.pdir = sm.validate_instance_directory(pdir=pdir)

class Requests:
    def __init__(self, inst):
        """
        Requests operates on a passed-in test_Main instance.
        :param inst Argument for instance passed through the classname.
        """
        sm.validate_instance(inst=inst)
        self.m = inst
        self.pdir = self.m.pdir

        # Directory Initialization
        self.class_dir = self.pdir / "Requests"
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

    ### Requests Methods ###
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
        Check if two Requests instances point to the same directory.

        Returns:
            bool: True if same type and same path.
        """
        return isinstance(other, Requests) and self.class_dir == other.class_dir

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
def temp_Requests(tmp_path):
    """Creates a Requests instance with a temporary directory."""
    main = test_Main(pdir=tmp_path)
    instance = Requests(inst=main)
    return instance

def test_repr_returns_expected_string(temp_Requests):
    result = repr(temp_Requests)
    assert result.startswith("<Requests path='")
    assert str(temp_Requests.class_dir) in result

def test_str_returns_human_readable(temp_Requests):
    expected_prefix = f"Requests at '{temp_Requests.class_dir}' with"
    assert str(temp_Requests).startswith(expected_prefix)

def test_bool_true_when_valid_dir(temp_Requests):
    assert bool(temp_Requests) is True

def test_bool_false_when_path_deleted(tmp_path):
    main = test_Main(pdir=tmp_path)
    instance = Requests(inst=main)
    instance.class_dir.rmdir()
    assert bool(instance) is False

def test_eq_same_path_same_object(tmp_path):
    main1 = test_Main(pdir=tmp_path)
    main2 = test_Main(pdir=tmp_path)
    c1 = Requests(inst=main1)
    c2 = Requests(inst=main2)
    assert c1 == c2


def test_eq_different_path_objects(tmp_path):
    path_a = tmp_path / "a"
    path_b = tmp_path / "b"
    path_a.mkdir()
    path_b.mkdir()

    main1 = test_Main(pdir=path_a)
    main2 = test_Main(pdir=path_b)
    c1 = Requests(inst=main1)
    c2 = Requests(inst=main2)

    assert c1 != c2

def test_len_counts_files_correctly(temp_Requests):
    temp_Requests.refresh()  # Ensure accurate baseline
    initial_count = len(temp_Requests)

    (temp_Requests.class_dir / "file1.txt").write_text("A")
    (temp_Requests.class_dir / "file2.txt").write_text("B")
    temp_Requests.refresh()

    expected = initial_count + 2
    assert len(temp_Requests) == expected

def test_contains_checks_file_by_name(temp_Requests):
    (temp_Requests.class_dir / "testfile.txt").write_text("data")
    temp_Requests.refresh()
    assert "testfile.txt" in temp_Requests
    assert "nonexistent.txt" not in temp_Requests

def test_getitem_returns_path_by_index(temp_Requests):
    file1 = temp_Requests.class_dir / "file1.txt"
    file2 = temp_Requests.class_dir / "file2.txt"
    file1.write_text("one")
    file2.write_text("two")
    temp_Requests.refresh()
    assert temp_Requests[0].name in {"file1.txt", "file2.txt"}
    assert isinstance(temp_Requests[0], Path)

def test_iter_yields_all_contents(temp_Requests):
    files = ["a.txt", "b.txt", "c.txt"]
    for name in files:
        (temp_Requests.class_dir / name).write_text("data")
    temp_Requests.refresh()
    names = [f.name for f in temp_Requests]
    for name in files:
        assert name in names

def test_refresh_updates_internal_file_list(temp_Requests):
    temp_Requests.refresh()  # Ensure contents is accurate
    initial_count = len(temp_Requests)

    new_file = temp_Requests.class_dir / "new.txt"
    new_file.write_text("added later")

    temp_Requests.refresh()
    assert len(temp_Requests) == initial_count + 1
    assert "new.txt" in temp_Requests

### Tests for Method ###

def test_dynamic_method_returns_argument(temp_Requests):
    """Ensure dynamic_method echoes the input value using instance."""
    assert temp_Requests.dynamic_method("value") == "value"
    assert temp_Requests.dynamic_method(123) == 123


def test_class_method_returns_class_name():
    """Ensure class_method returns the name of the classname as a string."""
    result = Requests.class_method()
    assert isinstance(result, str)
    assert result == "Requests"


def test_static_method_returns_argument():
    """Ensure static_method echoes the input value."""
    assert Requests.static_method("static") == "static"
    assert Requests.static_method(42) == 42


### Deprecated

    def request(self, url, method="GET", headers=None, data=None, json_data=None, files=None,
                as_text=True, timeout=(5, 10), retry_on_status=(500, 502, 503, 504), message: str = None):

        def request_fn():
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                data=data,
                json=json_data,
                files=files,
                timeout=timeout
            )
            if response.status_code in retry_on_status:
                raise requests.HTTPError(f"Retryable status: {response.status_code}")
            return response

        response, duration = self.timer(lambda: self.attempt(request_fn, message=message))
        log.info(f"Request to {url} succeeded in {duration:.2f}s with status {response.status_code}")
        return response.text if as_text else response.content

    def is_valid_file_size(self, path: str, max_size_mb: float) -> bool:
        """Check if the file or folder at `dir` is below the size limit."""
        total_size = 0

        if os.path.isfile(path):
            total_size = os.path.getsize(path)
        elif os.path.isdir(path):
            for dirpath, dirnames, filenames in os.walk(path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if os.path.isfile(fp):
                        total_size += os.path.getsize(fp)

        size_mb = total_size / (1024 * 1024)
        log.info(f"Computed size for {path}: {size_mb:.2f} MB")
        return size_mb <= max_size_mb

    @staticmethod
    def compute_sha256(buffer: bytes) -> str:
        """Compute SHA-256 hash of in-memory buffer."""
        hasher = hashlib.sha256()
        hasher.update(buffer)
        return hasher.hexdigest()

    def build_payload(self, filepaths: list[str] = None, dirs: list[str] = None,
                      max_size_mb: float = 10.0, archive_name: str = "data.zip") -> tuple:
        """Zips files and directories into an in-memory archive for upload."""

        log_buffer = io.BytesIO()
        with zipfile.ZipFile(log_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for path in filepaths or []:
                if os.path.isfile(path):
                    if not self.is_valid_file_size(path, max_size_mb):
                        raise ValueError(f"File exceeds {max_size_mb}MB: {path}")
                    zipf.write(path, arcname=os.path.basename(path))
                else:
                    log.warning(f"Skipping invalid file: {path}")

            for folder in dirs or []:
                if os.path.isdir(folder):
                    if not self.is_valid_file_size(folder, max_size_mb):
                        raise ValueError(f"Directory exceeds {max_size_mb}MB: {folder}")
                    for root, _, files in os.walk(folder):
                        for file in files:
                            abs_path = os.path.join(root, file)
                            rel_path = os.path.relpath(abs_path, start=folder)
                            arcname = os.path.join(os.path.basename(folder), rel_path)
                            zipf.write(abs_path, arcname=arcname)
                else:
                    log.warning(f"Skipping invalid directory: {folder}")

        log_buffer.seek(0)
        archive_bytes = log_buffer.getvalue()
        hash_value = self.compute_sha256(archive_bytes)
        size_kb = round(len(archive_bytes) / 1024, 2)

        files = {
            'archive': (archive_name, io.BytesIO(archive_bytes), 'application/zip')
        }
        metadata = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "archive_name": archive_name,
            "archive_size_kb": size_kb,
            "sha256": hash_value
        }

        return files, metadata

    def upload(self, url: str, filepaths: list[str] = None, dirs: list[str] = None, fields: dict = None,
               headers: dict = None, max_size_mb: float = 10.0, message: str = None) -> tuple[str, dict] | None:
        """Uploads zipped files/dirs via POST. Returns (response_text, metadata) or None."""
        try:
            files, metadata = self.build_payload(filepaths=filepaths, dirs=dirs, max_size_mb=max_size_mb)
            response = self.request(
                url=url,
                method="POST",
                headers=headers,
                data=fields,
                files=files,
                as_text=True,
                message=message or "Uploading data"
            )
            return response, metadata
        except Exception as e:
            log.error(f"Upload failed: {e}")
            return None
