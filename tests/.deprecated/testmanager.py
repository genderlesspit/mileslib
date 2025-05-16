import os
import importlib.util
import inspect
import jinja2 as j2
import pytest

class TestManager:
    def __init__(self, mileslib, dir: str = None, quiet: bool = None, overwrite: bool = False):
        #Parameters
        self.m = mileslib
        self.dir = dir
        self.quiet = quiet
        self.overwrite = overwrite

        #Initialize Tests dir
        self.tests_dir, self.tests_dir_exists = self.m.exists("tests", create_if_missing=True, disp="Tests dir")
        self.fixtures_dir, self.fixtures_dir_exists = self.m.exists("tests", "fixtures", create_if_missing=True, disp="Fixtures dir")

        #Initialize templates

        self.tests_template, self.tests_template_exists = self.m.exists("config", "test_templates.txt")
        if self.tests_template_exists is False: self.m.github.get("config", "test_templates.txt")
        self.fixture_template, self.fixture_template_exists = self.m.exists("config", "fixture_templates.txt")
        if self.fixture_template_exists is False: self.m.github.get("config", "fixture_templates.txt")
        self.static_fixture_template, self.static_fixture_template_exists = self.m.exists("config", "static_fixture_templates.txt")
        if self.static_fixture_template_exists is False: self.m.github.get("config", "static_fixture_templates.txt")
        self.run_test_gen(overwrite=True)

    def run_test_gen(self, overwrite=True):
        """
        :param overwrite: Overwrite existing test files if True
        """
        try:
            # 1. Discover both class/method structure and static files
            self.m.log.info("Starting discovery for modules and static files...")
            discovery_map, static_files = self.discover(static_fixtures=True)

            # 2. Generate both class + static file fixtures
            self.m.log.info("Generating all fixtures (class + static)...")
            self.generate_all_fixtures(
                discovery_map=discovery_map,
                static_files=static_files
            )

            # 3. Generate test method stubs
            self.m.log.info("Generating one-file-per-method test stubs...")
            self.generate_test_stub(discovery_map, overwrite=overwrite)

            self.m.log.info("Test stub and fixture generation completed successfully.")
        except Exception as e:
            self.m.crash(f"run_test_gen failed: {e}")

    class Template:
        @staticmethod
        def load(mileslib, path: str,) -> str:
            m = mileslib
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                m.crash(f"Could not load test template: {e}")
                return ""

        @staticmethod
        def render(template_text: str, context: dict) -> str:
            try:
                template = j2.Template(template_text)
                return template.render(**context)
            except Exception as e:
                return f"Template rendering failed: {e}"

    def discover(self,
                 dir: str = None,
                 quiet: bool = False,
                 static_fixtures: bool = False):
        """
        Discover .py modules and optionally collect all non-.py static files (recursively).
        Returns either:
          - discovery_map only
          - (discovery_map, static_files)
        """
        dir = self.dir or dir
        quiet = self.quiet or quiet

        discovery_map = {}
        static_files = []
        EXCLUDE_DIRS = {".git", ".venv", "__pycache__", ".idea", "site-packages", "logs", ".pytest_cache"}

        # ──────────────── RECURSIVE WALK ────────────────
        for root, dirs, files in os.walk(dir):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for filename in files:
                fullpath = os.path.join(root, filename)
                relpath = os.path.relpath(fullpath, self.m.dir)

                # Handle static fixtures
                if static_fixtures and not filename.lower().endswith(".py"):
                    base = os.path.splitext(filename)[0]
                    fixture_name = base.replace("-", "_").replace(" ", "_")
                    static_files.append({
                        "name": fixture_name,
                        "fullpath": fullpath,
                        "relpath": relpath
                    })
                    self.m.log.info(f"TestManager found static fixture at {fullpath}", quiet=quiet)
                    continue

                # Skip test, private, or irrelevant Python files
                if not filename.lower().endswith(".py") or filename.startswith(("test_", "__", ".")):
                    continue

                # Load and inspect valid Python module
                name = filename[:-3]
                if name in discovery_map:
                    continue  # skip duplicates if nested

                spec = importlib.util.spec_from_file_location(name, fullpath)
                if not spec or not spec.loader:
                    self.m.crash(f"Failed to create import spec for: {name}")
                    continue

                module = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(module)
                except Exception as e:
                    self.m.crash(f"Error loading module {name}: {e}")
                    continue

                class_map = {}
                for class_name, cls in inspect.getmembers(module, inspect.isclass):
                    if cls.__module__ != name:
                        continue

                    self.m.log.info(f"PlaceholderClass: {class_name} found.")

                    methods = [
                        method_name for method_name, _ in
                        inspect.getmembers(cls, inspect.isfunction)
                        if not method_name.startswith("_")
                    ]

                    if methods:
                        class_map[class_name] = methods

                if class_map:
                    discovery_map[filename] = class_map

        return (discovery_map, static_files) if static_fixtures else discovery_map

    def generate_test_stub(self, discovery_map: dict, test_dir: str = "tests", overwrite: bool = False):
        test_dir = self.tests_dir or test_dir
        template_text = self.Template.load(self.m, self.tests_template)

        for module_name, class_map in discovery_map.items():
            module_base = os.path.splitext(os.path.relpath(module_name, self.dir))[0].replace(os.sep, "/")

            for class_name, methods in class_map.items():
                class_dir = os.path.join(test_dir, module_base, class_name)
                os.makedirs(class_dir, exist_ok=True)

                for method_name in methods:
                    context = {
                        "module_name": module_base,
                        "class_name": class_name,
                        "method_name": method_name
                    }

                    rendered = self.Template.render(template_text, context)
                    test_file_path = os.path.join(class_dir, f"test_{method_name}.py")

                    if os.path.exists(test_file_path) and not overwrite:
                        self.m.log.warning(f"Skipped existing test: {test_file_path}")
                        continue

                    with open(test_file_path, "w", encoding="utf-8") as f:
                        f.write(rendered)

                    self.m.log.info(f"Generated test stub: {test_file_path}")

    def generate_all_fixtures(self,
                              discovery_map: dict,
                              static_files: list[dict] = None,
                              test_dir: str = "tests",
                              fixture_tpl: str = None,
                              static_tpl: str = None):
        """
        Combines:
          - PlaceholderClass-based fixtures per module in tests/<module>/conftest.py
          - Static file fixtures in tests/conftest.py

        :param discovery_map: {module.py: {ClassName: [methods]}}
        :param static_files: optional list of static files:
                             [{"name":..., "fullpath":..., "relpath":...}, ...]
        :param test_dir: destination base test folder
        :param fixture_tpl: template path for class fixtures
        :param static_tpl: template path for static file fixtures
        """
        test_dir     = self.tests_dir or test_dir
        fixture_tpl  = self.fixture_template or fixture_tpl
        static_tpl   = self.static_fixture_template or static_tpl

        # ─────────────────────────────────────────────────────
        # 1. Per-module class fixtures → tests/<module>/conftest.py
        # ─────────────────────────────────────────────────────
        if fixture_tpl and discovery_map:
            with open(fixture_tpl, "r", encoding="utf-8") as f:
                tpl_text = f.read()

            for module_file, classes in discovery_map.items():
                module_base = module_file.replace(".py", "")
                module_test_dir = os.path.join(test_dir, module_base)
                os.makedirs(module_test_dir, exist_ok=True)

                rendered = j2.Template(tpl_text).render(
                    module_name=f"mileslib.{module_base}",
                    classes=list(classes.keys())
                )
                conftest_path = os.path.join(module_test_dir, "conftest.py")
                with open(conftest_path, "w", encoding="utf-8") as cf:
                    cf.write(rendered)
                self.m.log.info(f"Generated class-based fixtures: {conftest_path}")

        # ─────────────────────────────────────────────────────
        # 2. Global static fixtures → tests/conftest.py
        # ─────────────────────────────────────────────────────
        if static_tpl and static_files:
            with open(static_tpl, "r", encoding="utf-8") as f:
                tpl_text = f.read()

            fixtures_ctx = []
            for item in static_files:
                fixtures_ctx.append({
                    "name":     item["name"],
                    "filename": os.path.basename(item["fullpath"]),
                    "relpath":  item["relpath"]
                })

            rendered = j2.Template(tpl_text).render(static_files=fixtures_ctx)
            conftest_path = os.path.join(test_dir, "conftest.py")
            with open(conftest_path, "w", encoding="utf-8") as cf:
                cf.write(rendered)
            self.m.log.info(f"Generated static-file fixtures: {conftest_path}")

