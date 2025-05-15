import json
import os
from pathlib import Path
from staticmethods import StaticMethods as sm

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