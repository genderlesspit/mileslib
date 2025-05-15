import pytest
import json
import os
from pathlib import Path
from staticmethods import StaticMethods as sm

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

    @staticmethod
    def build_config(cfg_dir):
        file = os.path.join(cfg_dir, "config.json")
        if os.path.exists(file):
            build: Path = sm.validate_file(file)
            return build
        else:
            build: Path = sm.ensure_file_with_default("config/config.json",
                                                        default={"app_name": "MilesApp", "version": "1.0"})
            return build

    def get(self, *args: str | list | tuple):
        file = self.cfg_file
        for arg in args:
            if not isinstance(arg, (str, int)):
                raise TypeError(f"Invalid path for config.get(): {arg!r} must be str, list, or int")

        def load_and_traverse():
            if os.stat(file).st_size == 0:
                sm.ensure_file_with_default("config/config.json",
                                                        default={"app_name": "MilesApp", "version": "1.0"})
            with open(file, "r", encoding="utf-8") as f:
                config_data = json.load(f)

            return sm.traverse_dictionary(config_data, *args)

        try:
            setting = sm.recall(
                fn=load_and_traverse,
                max_attempts=3,
                handled_exceptions=(json.JSONDecodeError, FileNotFoundError)
            )

            if setting is None:
                raise Exception(f"Requested setting not found in {file}. Please amend.")
            return setting

        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON in {file}: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading {file}: {e}")

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
    assert config_class.get("app_name") == "MilesApp"
    assert config_class.get("version") == "1.0"
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

    def get(self, *args):
        return setting

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
    '''
    Tests whether get() can handle a miscellaneous, unexpected error.
    '''
    def raise_weird_error():
        raise ValueError("Weird stuff")

    monkeypatch.setattr("staticmethods.StaticMethods.recall", lambda *a, **kw: raise_weird_error())

    with pytest.raises(RuntimeError, match="Unexpected error reading"):
        config_class.get("app_name")