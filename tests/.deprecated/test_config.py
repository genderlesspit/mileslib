import pytest
import json
import os
from pathlib import Path
from tests.mileslib_core import StaticMethods as sm
from tests.mileslib_core import Logger as log

class Main:
    def __init__(self, pdir = None):
        self.sm = sm #Static Methods
        self.pdir = pdir

class Config:
    def __init__(self, inst):
        """
        Initializes the Config class for the client. A subclass of the main MilesLib instance.
        Validates the incoming instance and its directory before proceeding.
        """
        sm.validate_instance(inst=inst)
        self.m = inst
        self.pdir = sm.validate_instance_directory(pdir=self.m.pdir)

        # Directory Initialization
        self.cfg_dir = os.path.join(self.pdir, "config")
        sm.validate_directory(self.cfg_dir)
        self.cfg_file = self.build_config(self.cfg_dir)

        #required keys
        self.required_keys = [
            "valid", "setup_complete", "local_version", "repo_url", "token",
            "dependencies", "paths", "profile", "env_overrides", "env",
            "required", "denylist", "defaults", "meta"
        ]
        self.denylist = ["changeme", ""]

    @staticmethod
    def build_config(cfg_dir: Path, mileslib=None) -> Path:
        """
        Ensures a config.json exists at the given path.
        If missing, attempts to download from the configured GitHub repo.

        Args:
            cfg_dir (Path): Local config directory
            mileslib (optional): MilesLib instance used to fetch from GitHub

        Returns:
            Path: Path to the valid config.json
        """
        file = cfg_dir / "config.json"

        if file.exists():
            return sm.validate_file(file)

        # Attempt to pull from GitHub if mileslib is provided
        if mileslib:
            mileslib.log.info("Local config.json missing. Attempting to pull from GitHub...")
            github = Github(mileslib, dir=str(cfg_dir))
            github.get("config", "config.json")

        # After GitHub attempt, either validate or write default
        if file.exists():
            return sm.validate_file(file)
        else:
            return sm.ensure_file_with_default(file, default={"valid": True})

    def ensure_setup(self):
        """
            Performs one-time validation that config.json is valid and all required fields are set.
            - Checks required env vars
            - Enforces denylist
            - Ensures paths exist
            - Confirms setup flag is True
            - Raises RuntimeError if any issues found
            """
        #Validate top-level config
        top_level = self.require(self.required_keys, denylist=self.denylist)
        self.build_config(cfg_dir=self.cfg_dir) if top_level is not True or Exception else log.info("Config top-level setup successfully initialized.")

        # Ensure critical paths exist
        paths = self.get("paths")
        for label, raw_path in paths.items():
            path_obj = Path(raw_path)
            if "log" in label or "dir" in label:
                sm.validate_directory(path_obj)
            elif ".env" in label or path_obj.suffix:
                sm.ensure_file_with_default(path_obj, default="")

            # Optional: enforce setup_complete is true
        if not self.get("setup_complete"):
            raise RuntimeError("Project setup incomplete. Please set 'setup_complete': true in config.json.")

        # Optional: check token exists if your CLI uses it
        token = self.get("token")
        if not token or token in self.denylist:
            raise RuntimeError("Missing or insecure token value in config.json.")

    def get(self, *args: str | list | tuple, default=None, expected=None):
        """
        Retrieve a value from config.json using a key path.
        Supports a fallback default and value validation.

        Args:
            *args: Path into nested config (e.g., "env", "POSTGRES_DB").
            default: Value to return if the key path is missing.
            expected: If set, raises ValueError if retrieved value does not match.

        Returns:
            The retrieved config value.

        Raises:
            RuntimeError: If the config file is missing, unreadable, or empty.
            ValueError: If `expected` is set and the retrieved value doesn't match.
        """
        file = self.cfg_file

        for arg in args:
            if not isinstance(arg, (str, int)):
                raise TypeError(f"Invalid path for config.get(): {arg!r} must be str or int")

        def load_and_traverse():
            if os.stat(file).st_size == 0:
                sm.ensure_file_with_default(file, default={"valid": True})
            with open(file, "r", encoding="utf-8") as f:
                config_data = json.load(f)
            return sm.traverse_dictionary(config_data, *args, default=default)

        try:
            setting = sm.recall(
                fn=load_and_traverse,
                max_attempts=3,
                handled_exceptions=(json.JSONDecodeError, FileNotFoundError)
            )

            joined_path = " → ".join(map(str, args))

            if setting is None:
                raise Exception(f"Missing config key path: {joined_path} in {file}")

            if expected is not None and setting != expected:
                raise ValueError(f"Value mismatch at {joined_path}: expected {expected!r}, got {setting!r}")

            return setting

        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON in {file}: {e}")
        except ValueError as e:
            if "Value mismatch" in str(e):
                raise
            else:
                raise RuntimeError(f"Unexpected error reading {file}: {e}")
        except TypeError:
            raise  # Let type validation bubble up
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading {file}: {e}")

    def require(
            self,
            keys: list[str],
            *,
            root: str = "env",
            denylist: list[str] = None
    ):
        """
        Ensures that required config keys exist and are not in a denylist of invalid values.

        Args:
            keys (list[str]): Keys to validate.
                - If root is None, keys are expected at the top level.
                - If root is set (e.g., "env"), keys are expected under that section.
            root (str | None): Section of config to check keys in (default is "env").
                Use None to check top-level keys directly.
            denylist (list[str], optional): List of unacceptable values (e.g., "", "changeme").

        Raises:
            RuntimeError: If any keys are missing or contain denylisted values.

        Returns:
            bool: True if all keys are present and valid.
        """
        missing = []
        bad = []

        for key in keys:
            try:
                if root:
                    val = self.get(root, key)
                else:
                    val = self.get(key)
                if denylist and val in denylist:
                    bad.append((key, val))
            except Exception:
                missing.append(key)

        if missing or bad:
            msg = ""
            if missing:
                msg += f"Missing keys: {missing}\n"
            if bad:
                msg += f"Invalid values: {bad}\n"
            raise RuntimeError(msg.strip())

        return True

    @property
    def raw(self):
        with open(self.cfg_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def dump(self):
        print(json.dumps(self.raw, indent=2))

##TESTING##

@pytest.fixture
def main_class(tmp_path):
    return Main(pdir=tmp_path)

@pytest.fixture
def config_class(main_class):
    return Config(inst=main_class)

def test_config_init_broken_instance(broken_instance):
    '''
    Tests whether get() can handle the user messing up the directories in whatever which way.
    :param broken_directory Simulates a broken directory for Config() initialization
    '''
    with pytest.raises(AttributeError):
        Config(inst=broken_instance)

def test_config_init_broken_directories(broken_main_directory):
    """
    Tests whether Config fails when passed a syntactically broken or invalid path.
    """
    with pytest.raises(FileNotFoundError):
        Config(inst=broken_main_directory)

def test_config_class_directory_exists(config_class):
    assert os.path.isdir(config_class.cfg_dir), f"Expected directory does not exist: {config_class.cfg_dir}"

def test_config_class_file_exists(config_class):
    assert os.path.isfile(config_class.cfg_file), f"Config file missing at: {config_class.cfg_file}"

#Config get(args*)
def test_config_get_reads_json(config_class):
    '''
    Tests whether get() can read config.json
    :param config_class Instance of Config()
    '''
    assert config_class.get("valid") == True
    # Expect an error when a key does not exist
    with pytest.raises(RuntimeError):
        config_class.get("nonexistent")

def test_config_get_input_is_not_path(config_class):
    '''
    Tests whether get() can handle TypeErrors
    :param config_class Instance of Config()
    '''
    with pytest.raises(RuntimeError):
        config_class.get(123)
    with pytest.raises(TypeError):
        config_class.get(None)
    with pytest.raises (TypeError):
        config_class.get(["list"])
    pass

def test_config_get_json_breaks(config_class):
    '''
    Tests whether get() raises an error when the JSON content is malformed.
    '''
    # Overwrite config file with invalid JSON
    with open(config_class.cfg_file, "w", encoding="utf-8") as f:
        f.write("{ invalid json ")

    with pytest.raises(RuntimeError, match="Invalid JSON"):
        config_class.get("app_name")


def test_config_get_cfg_file_not_found(config_class):
    '''
    Tests whether get() raises an error when the config file is missing.
    '''
    os.remove(config_class.cfg_file)

    with pytest.raises(RuntimeError, match="Unexpected error reading"):
        config_class.get("app_name")


def test_config_get_unknown_error(config_class, monkeypatch):
    """
    Tests whether get() can handle a miscellaneous, unexpected error.
    """
    # Patch recall to raise when called
    monkeypatch.setattr(
        sm, "recall",
        lambda *a, **kw: (_ for _ in ()).throw(ValueError("Weird stuff"))
    )

    with pytest.raises(RuntimeError, match="Unexpected error reading"):
        config_class.get("app_name")

class DummyInst:
    def __init__(self, pdir):
        self.pdir = pdir

@pytest.fixture
def config_with_values(tmp_path):
    """Creates config.json with nested and top-level keys."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    data = {
        "top": "value",
        "env": {
            "DEBUG": True,
            "TIMEOUT": 30
        }
    }

    config_path = config_dir / "config.json"
    config_path.write_text(json.dumps(data, indent=2))

    inst = DummyInst(pdir=tmp_path)
    return Config(inst=inst)

def test_get_returns_default_if_key_missing(config_with_values):
    cfg = config_with_values
    result = cfg.get("not_real", default="fallback")
    assert result == "fallback"

def test_get_returns_default_nested(config_with_values):
    cfg = config_with_values
    result = cfg.get("env", "MISSING", default=False)
    assert result is False

def test_get_expected_value_matches(config_with_values):
    cfg = config_with_values
    result = cfg.get("env", "DEBUG", expected=True)
    assert result is True

def test_get_expected_value_fails(config_with_values):
    cfg = config_with_values
    with pytest.raises(ValueError) as e:
        cfg.get("env", "TIMEOUT", expected=60)
    assert "Value mismatch" in str(e.value)

def test_get_expected_with_default_match(config_with_values):
    cfg = config_with_values
    result = cfg.get("env", "UNDEFINED", default="test", expected="test")
    assert result == "test"

def test_get_expected_with_default_mismatch(config_with_values):
    cfg = config_with_values
    with pytest.raises(ValueError) as e:
        cfg.get("env", "UNDEFINED", default="abc", expected="xyz")
    assert "Value mismatch" in str(e.value)

def test_get_missing_key_raises_without_default(config_with_values):
    cfg = config_with_values
    with pytest.raises(RuntimeError) as e:
        cfg.get("env", "DOES_NOT_EXIST")
    assert "Missing config key path" in str(e.value)

class DummyInst:
    """Minimal dummy instance with a project directory."""
    def __init__(self, pdir):
        self.pdir = pdir

@pytest.fixture
def test_config(tmp_path):
    """Creates a temporary config.json and Config instance."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    config_path = config_dir / "config.json"
    config_path.write_text("""
    {
        "env": {
            "POSTGRES_DB": "mileslib",
            "POSTGRES_USER": "postgres",
            "POSTGRES_PASSWORD": "supersecret",
            "DJANGO_CLIENT_ID": "real-id",
            "DJANGO_CLIENT_SECRET": "real-secret",
            "DJANGO_TENANT_ID": "tenant"
        },
        "required": [
            "POSTGRES_DB",
            "POSTGRES_USER",
            "POSTGRES_PASSWORD",
            "DJANGO_CLIENT_ID",
            "DJANGO_CLIENT_SECRET",
            "DJANGO_TENANT_ID"
        ],
        "denylist": ["changeme", ""]
    }
    """)

    dummy = DummyInst(pdir=tmp_path)
    cfg = Config(inst=dummy)
    return cfg

def test_require_passes_with_valid_config(test_config):
    assert test_config.require(
        test_config.raw["required"],
        denylist=test_config.raw["denylist"]
    ) is True

def test_require_raises_for_missing_keys(test_config):
    # Remove a key
    data = test_config.raw
    del data["env"]["POSTGRES_DB"]

    test_config.cfg_file.write_text(
        json.dumps(data, indent=2)
    )

    with pytest.raises(RuntimeError) as e:
        test_config.require(data["required"], denylist=data["denylist"])

    assert "Missing keys" in str(e.value)

def test_require_raises_for_denylisted_value(test_config):
    # Set a bad value
    data = test_config.raw
    data["env"]["POSTGRES_PASSWORD"] = "changeme"

    test_config.cfg_file.write_text(
        json.dumps(data, indent=2)
    )

    with pytest.raises(RuntimeError) as e:
        test_config.require(data["required"], denylist=data["denylist"])

    assert "Invalid values" in str(e.value)

def test_config_dump_valid_json(capsys, test_config):
    test_config.dump()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "env" in data

def test_require_partial_missing_and_bad(test_config):
    data = test_config.raw
    data["env"]["DJANGO_CLIENT_SECRET"] = "changeme"  # bad value
    del data["env"]["DJANGO_CLIENT_ID"]  # missing key

    test_config.cfg_file.write_text(
        json.dumps(data, indent=2)
    )

    with pytest.raises(RuntimeError) as e:
        test_config.require(data["required"], denylist=data["denylist"])

    msg = str(e.value)
    assert "Missing keys" in msg
    assert "Invalid values" in msg

def test_require_passes_without_denylist(test_config):
    required = test_config.raw["required"]
    assert test_config.require(required) is True

class DummyInst:
    def __init__(self, pdir):
        self.pdir = pdir

@pytest.fixture
def valid_config(tmp_path):
    """Create a valid, minimal config.json and Config instance."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "config.json"

    config_data = {
        "env": {
            "POSTGRES_DB": "db",
            "POSTGRES_USER": "user",
            "POSTGRES_PASSWORD": "securepass",
            "DJANGO_CLIENT_ID": "clientid",
            "DJANGO_CLIENT_SECRET": "secret",
            "DJANGO_TENANT_ID": "tenant"
        },
        "required": [
            "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD",
            "DJANGO_CLIENT_ID", "DJANGO_CLIENT_SECRET", "DJANGO_TENANT_ID"
        ],
        "denylist": ["", "changeme"],
        "setup_complete": True,
        "token": "secure-token",
        "paths": {
            "log_dir": str(tmp_path / "logs"),
            "env_file": str(tmp_path / ".env")
        }
    }

    config_path.write_text(json.dumps(config_data, indent=2))
    dummy = DummyInst(pdir=tmp_path)
    cfg = Config(inst=dummy)
    return cfg

def test_ensure_setup_success(valid_config):
    valid_config.ensure_setup()


def test_ensure_setup_fails_on_missing_required(valid_config):
    data = valid_config.raw
    del data["env"]["POSTGRES_USER"]
    valid_config.cfg_file.write_text(json.dumps(data, indent=2))

    with pytest.raises(RuntimeError) as e:
        valid_config.ensure_setup()
    assert "Missing" in str(e.value)


def test_ensure_setup_fails_on_denylisted_value(valid_config):
    data = valid_config.raw
    data["env"]["POSTGRES_PASSWORD"] = "changeme"
    valid_config.cfg_file.write_text(json.dumps(data, indent=2))

    with pytest.raises(RuntimeError) as e:
        valid_config.ensure_setup()
    assert "Invalid values" in str(e.value)


def test_ensure_setup_fails_if_setup_flag_false(valid_config):
    data = valid_config.raw
    data["setup_complete"] = False
    valid_config.cfg_file.write_text(json.dumps(data, indent=2))

    with pytest.raises(RuntimeError) as e:
        valid_config.ensure_setup()
    assert "setup_complete" in str(e.value)


def test_ensure_setup_fails_if_token_missing(valid_config):
    data = valid_config.raw
    del data["token"]
    valid_config.cfg_file.write_text(json.dumps(data, indent=2))

    with pytest.raises(RuntimeError) as e:
        valid_config.ensure_setup()
    assert "token" in str(e.value)


def test_ensure_setup_fails_if_token_denylisted(valid_config):
    data = valid_config.raw
    data["token"] = "changeme"
    valid_config.cfg_file.write_text(json.dumps(data, indent=2))

    with pytest.raises(RuntimeError) as e:
        valid_config.ensure_setup()
    assert "token" in str(e.value)
