import pytest
import json
import os
from pathlib import Path
from core import MilesLib
import staticmethods as sm

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
        self.m._validate_instance(inst=inst)
        self.m = inst
        self.pdir = self.m._validate_instance_directory(pdir=self.m.pdir)

        # Directory Initialization
        self.cfg_dir = os.path.join(self.pdir, "config")
        self.m._validate_directory(self.cfg_dir)
        self.cfg_file = os.path.join(self.cfg_dir, "config.json")
        self.m._validate_file(self.cfg_file)
        self.cfg_file = self.m._ensure_file_with_default(
            "config/config.json",
            default={"app_name": "MilesApp", "version": "1.0"}
        )

    #For External Use
    def get(self, *args: str):
        setting_path = list(args)
        try:
            with open(self.cfg_file, "r", encoding="utf-8") as f:
                settings = json.load(f)
        except Exception as e:
            pass

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
    assert config_class.get("nonexistent") is None

def test_config_get_input_is_not_path(config_class):
    '''
    Tests whether get() can handle TypeErrors
    :param config_class Instance of Config()
    '''
    with pytest.raises(TypeError):
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
    Tests an error in the json retrieval, maybe a syntax error...
    '''
    pass

def test_config_get_cfg_file_not_found(config_class):
    '''
    Tests whether the get function can handle requests when the config file is not found.
    :return:
    '''
    pass

def test_config_get_unknown_error(config_class):
    '''
    Tests whether the get function can handle a miscellaneous error.
    '''