from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Optional

import mileslib

from dotenv import load_dotenv
import os

class Global:
    instance = None

    def __init__(self, path: Path = None):
        self.path = path or Path.cwd
        _ = self.directory

    @classmethod
    def get_instance(cls, path: Path = None):
        path = path or None
        if cls.instance is None:
            cls.instance = cls(path)
        return cls.instance

    @cached_property
    def directory(self) -> Path:
        directory_path = self.path / ".mileslib"
        directory_path.mkdir(exist_ok=True)
        return directory_path

def main():
    Global()

if __name__ == "__main__":
    main()