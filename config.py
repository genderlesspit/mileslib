import json
import os

class Config:
    def __init__(self, mileslib, dir: str, quiet: bool = None):
        self.m = mileslib
        self.quiet = quiet or False
        self.dir = os.path.join(dir, "config")
        self.file = os.path.join(self.dir, "config.json")

        if not os.path.exists(self.file):
            os.makedirs(self.dir, exist_ok=True)
            with open(self.file, "w", encoding="utf-8") as f:
                json.dump({
                    "local_version": "0.0.0",
                    "repo_url": "https://raw.githubusercontent.com/your/repo/master",
                    "token": "",
                    "dependencies": {}
                }, f, indent=2)
            self.m.github.get("config", "config.json")

    def install_all_dependencies(self):
        try:
            deps = self.get("dependencies")
            if not isinstance(deps, dict):
                self.m.log.warning("No dependencies found in config.")
                return

            for name, entry in deps.items():
                dep = entry.get("dep")
                pack = entry.get("pack", dep)

                if dep:
                    self.m.log.info(f"Initializing dependency: {name} (import: '{dep}', pip: '{pack}')")
                    self.m.dependency(dep.strip(), pack.strip() if pack else dep.strip())
                else:
                    self.m.log.warning(f"Skipping dependency '{name}' — missing 'dep' key.")

        except Exception as e:
            self.m.crash(f"Issue with dependency retrieval: {e}")

    def check(self, *args: str):
        try:
            with open(self.file, "r", encoding="utf-8") as f:
                config_data = json.load(f)

            # Scroll Through Data
            current = config_data
            for key in args:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    self.m.log.warning(f"Missing config key: {' -> '.join(args)}")
                    return False
            self.m.log.info(f"Config value found for {' -> '.join(args)}: {current}")
            return True

        except Exception as e:
            self.m.crash(f"Config reading went wrong!: {e}")

    def get(self, *args: str):
        try:
            with open(self.file, "r", encoding="utf-8") as f:
                config_data = json.load(f)

            # Scroll Through Data
            current = config_data
            for key in args:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return None  # Key dir not found
            return current  # Final value

        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON in {self.file}: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading {self.file}: {e}")