from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

import mileslib

from dotenv import load_dotenv
import os

load_dotenv()  # or load_dotenv(dotenv_path=Path("custom.env"))

value = os.getenv("MY_VAR")

@dataclass(frozen=True)
class Project:
    name = str
    type = str
    path = Path
    cfg = Path

class GlobalDefaults:
    pass


@dataclass(frozen=True)
class Global:
    path: Path

    @cached_property
    def directory(self) -> Path:
        directory_path = self.path / ".mileslib"
        directory_path.mkdir(exist_ok=True)
        return directory_path

    @cached_property
    def cfg(self) -> Path:
        cfg_path = self.directory / "mileslib_settings.toml"
        mileslib.ensure_file(cfg_path, "")
        return cfg_path

    @cached_property
    def env(self) -> Path:
        env_path = self.directory / ".env"
        mileslib.ensure_file(env_path, "")
        return env_path

    @cached_property
    def projects(self) -> dict:
        found = {}
        for sub in self.path.iterdir():
            if not sub.is_dir() or sub.name.startswith("__") or "pycache" in sub.name.lower():
                continue
            cfg = sub / f"mileslib_{sub.name}_settings.toml"
            #if cfg.exists():
                #found[sub.name] = Project(
                #    name=sub.name,
                #    path=sub,
                #    cfg=cfg,
                #)
        return found

    def __post_init__(self):
        _ = self.directory
        _ = self.cfg
        _ = self.env
        _ = self.projects

def main():
    Global(Path.cwd())

if __name__ == "__main__":
    main()