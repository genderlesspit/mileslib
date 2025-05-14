import pytest

@pytest.fixture
def broken_directory():
    return r"]\[]x//f"

@pytest.fixture
def broken_main_directory(broken_directory):
    class BrokenMain:
        def __init__(self):
            self.pdir = broken_directory
    return BrokenMain()

@pytest.fixture
def sample_string():
    """
    Returns a generic sample string.

    Example:
        def test_uppercase(sample_string):
            assert sample_string.upper() == "EXAMPLE"
    """
    return "example"


@pytest.fixture
def sample_object():
    """
    Returns a basic dummy object with one attribute.

    Example:
        def test_attr_access(sample_object):
            assert sample_object.value == 42
    """
    class Dummy:
        def __init__(self):
            self.value = 42
    return Dummy()


@pytest.fixture
def sample_tuple():
    """
    Returns a generic tuple with mixed types.

    Example:
        def test_unpack(sample_tuple):
            a, b, c = sample_tuple
            assert isinstance(b, str)
    """
    return (1, "two", 3.0)


@pytest.fixture
def missing_file_path(tmp_path):
    """
    Returns a path to a non-existent file in a temp directory.

    Example:
        def test_missing_file_handling(missing_file_path):
            with pytest.raises(FileNotFoundError):
                open(missing_file_path, 'r')
    """
    return tmp_path / "nonexistent_file.json"


@pytest.fixture
def broken_instance():
    """
    Returns an object that raises AttributeError for all attribute access.

    Example:
        def test_broken_instance(broken_instance):
            with pytest.raises(AttributeError):
                broken_instance.some_attr
    """
    class Broken:
        def __getattr__(self, name):
            raise AttributeError(f"{name} is broken")
    return Broken()


@pytest.fixture
def numeric_values():
    """
    Returns a list of edge-case numeric values.

    Example:
        def test_numeric_range(numeric_values):
            assert all(isinstance(n, (int, float)) for n in numeric_values)
    """
    return [0, -1, 1, 3.14, float('inf'), float('-inf'), float('nan')]


@pytest.fixture
def falsy_values():
    """
    Returns a list of common falsy values in Python.

    Example:
        def test_truthiness(falsy_values):
            for val in falsy_values:
                assert not val
    """
    return [None, False, 0, "", [], {}, set()]


@pytest.fixture
def non_string_keys():
    """
    Returns a list of common non-string keys for dict testing or type validation.

    Example:
        def test_non_string_key_raises(non_string_keys):
            for key in non_string_keys:
                with pytest.raises(TypeError):
                    some_dict = {key: "value"}  # assuming only str keys allowed
    """
    return [123, None, True, 3.14, ("tuple",), object()]
