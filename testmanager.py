import os
import importlib.util
import inspect
import pytest
import jinja2

class TestManager:
    def __init__(self, mileslib, dir: str = None, quiet: bool = None):
        self.m = mileslib
        self.dir = dir
        self.quiet = quiet
        self.tests_dir, self.tests_dir_exists = self.m.exists("tests", create_if_missing=True, disp="Tests directory")
        self.tests_template, self.tests_template_exists = self.m.exists("config", "test_templates.txt")
        if self.tests_template_exists is False: self.m.github.get("config", "test_templates.txt")

    def discover(self, dir: str = None, quiet: bool = False):
        # Initializing Variables
        dir = self.dir or dir
        quiet = self.quiet or quiet

        discovery_map = {}

        #Going through files in main dir
        for filename in os.listdir(dir):
            if not filename.lower().endswith(".py") or filename.startswith(("test_", "__", ".")):
                continue

            self.m.log.info(f"TestManager found Module at {dir}", quiet=quiet)
            name = filename[:-3] #strip.py
            path = os.path.join(dir, filename)
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                self.m.crash(f"Failed to create import spc for: {name}")
                continue

            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
            except Exception as e:
                self.m.crash(f"Error with TestManager module specification: {e}")
                continue

            class_map = {}

            for class_name, cls in inspect.getmembers(module, inspect.isclass):
                if cls.__module__ != name:
                    continue

                self.m.log.info(f"Class: {class_name} found.")

                methods = []

                for method_name, method in inspect.getmembers(cls, inspect.isfunction):
                    if method_name.startswith("_"):
                        continue #Skips functions with "_" at the front.
                    self.m.log.info(f"Method: {method} found.")
                    methods.append(method_name)

                if methods:
                    class_map[class_name] = methods

            if class_map:
                discovery_map[filename] = class_map

        return discovery_map

    def load_test_template(self) -> str:
        try:
            with open(self.tests_template, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            self.m.crash(f"Could not load test template: {e}")
            return ""


    def generate_test_stub(self, discovery_map: dict, test_dir: str = "tests"):
        pass
        #for module, classes in discovery_map.items():
        #   module_name =