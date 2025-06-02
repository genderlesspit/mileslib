import json
import os
from pathlib import Path
from typing import Any

import toml
import yaml

import context._globals as _globals
from context.envloader import env
from util import milesutil as mutil


class Config:
    """
    Flexible configuration manager supporting multi-format file loading and structured key access.

    Loads configuration from TOML, JSON, or YAML files and provides deep key retrieval,
    validation, and mergeable write-back functionality.

    File format is auto-detected based on file extension.
    """

    @staticmethod
    def configify(data: dict) -> dict:
        """
        Recursively convert all values in a dictionary to strings.
        Useful for sanitizing configuration values before serialization.

        Args:
            data (dict): The input dictionary with arbitrary value types.

        Returns:
            dict: A new dictionary with the same structure but all values as strings.

        Raises:
            TypeError: If input is not a dictionary.
        """
        if not isinstance(data, dict):
            raise TypeError("configify expects a dictionary")

        def stringify(val):
            if isinstance(val, dict):
                return {k: stringify(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [stringify(v) for v in val]
            elif isinstance(val, tuple):
                return tuple(stringify(v) for v in val)
            else:
                return str(val)

        return {k: stringify(v) for k, v in data.items()}

    @staticmethod
    def build(path):
        default = None
        file = None

        try:
            if Path(path).resolve() == Path(_globals.GLOBAL_CFG_FILE).resolve():
                default = _globals.GLOBAL_CFG_DEFAULT
                file = mutil.ensure_file(path, default)
            else:
                default = _globals.PROJECT_CFG_DEFAULT
                file = mutil.ensure_file(path, default)
        except Exception as e:
            raise RuntimeError(f"Could not build config!: {e}")

        if file is not None: return file

        raise FileNotFoundError

    @staticmethod
    def dump(path: Path = _globals.GLOBAL_CFG_FILE) -> dict:
        """
        Prints the current config file as formatted JSON for inspection.
        """
        if not _globals.GLOBAL_CFG_FILE.exists():
            Config.build(path=_globals.GLOBAL_CFG_FILE)

        if not mutil.check_types(path, expected=Path):
            raise FileNotFoundError

        file_ext = mutil.MFile.resolve_extension(path)

        def parse_toml(path: Path) -> dict:
            return toml.load(path)

        def parse_json(path: Path) -> dict:
            return json.loads(path.read_text(encoding="utf-8"))

        def parse_yaml(path: Path) -> dict:
            return yaml.safe_load(path.read_text(encoding="utf-8"))

        parsers = {
            "toml": parse_toml,
            "json": parse_json,
            "yaml": parse_yaml,
            "yml": parse_yaml,
        }

        try:
            if file_ext not in parsers:
                raise TypeError(f"[Config.dump] Unsupported config format: {file_ext}")
            parsed_data = parsers[file_ext](path)
            if not isinstance(parsed_data, dict):
                raise TypeError(f"[Config.dump] Parsed config is not a dict: {type(parsed_data)}")
            return parsed_data
        except Exception as e:
            raise RuntimeError(f"[Config.dump] Failed to parse config at {path}: {e}")

    @staticmethod
    def fetch(path: Path = _globals.GLOBAL_CFG_FILE) -> dict:
        """
        Ensures the config file exists, then loads and returns its parsed contents.

        Args:
            path (Path): Path to the config file.

        Returns:
            dict: Parsed configuration data.
        """

        def fallback():
            Config.build(path)
            return Config.dump(path)  # reload as dict

        loaded_cfg = mutil.recall(
            lambda: Config.dump(path),
            fallback
        )
        return loaded_cfg

    @staticmethod
    def get(*keys, path: Path = _globals.GLOBAL_CFG_FILE) -> Any:
        """
        Retrieves a nested configuration value from the loaded file.

        Supports chained key access (e.g., cfg.get("profile", "version")).

        Args:
            *keys: One or more keys to traverse the configuration hierarchy.
            path (Path): Path to the configuration file (default: _globals.GLOBAL_CFG_FILE).

        Returns:
            Any: The resolved value.

        Raises:
            RuntimeError: If keys are missing or config is malformed.
        """
        data = Config.fetch(path)
        print(f"[Config.get] Config successfully loaded: {data}")

        try:
            for key in keys:
                data = data[key]
            return data
        except (KeyError, TypeError) as e:
            raise RuntimeError(f"[Config.get] Key path {keys} not found or invalid: {e}")

    @staticmethod
    def deep_merge(target: dict, updates: dict):
        for k, v in updates.items():
            if isinstance(v, dict) and isinstance(target.get(k), dict):
                Config.deep_merge(target[k], v)
            else:
                target[k] = v

    @staticmethod
    def write(path: Path = _globals.GLOBAL_CFG_FILE, *, set: dict = None, add: dict = None,
              remove: list = None) -> None:
        """
        Edits the config file by setting, adding, or removing key-value pairs.

        Args:
            path (Path): Config file path to write (default: _globals.GLOBAL_CFG_FILE).
            set (dict): Overwrite existing keys or add new ones.
            add (dict): Add new keys only; does not overwrite existing ones.
            remove (list): List of top-level keys to delete.

        Raises:
            RuntimeError: If the config file cannot be read or written.
        """
        data = Config.fetch(path)

        if set:
            for k, v in set.items():
                if isinstance(v, dict) and isinstance(data.get(k), dict):
                    Config.deep_merge(data[k], v)
                else:
                    data[k] = v

        if add:
            for k, v in add.items():
                if k not in data:
                    data[k] = v

        if remove:
            for k in remove:
                data.pop(k, None)

        mutil.write(path=path, data=data, overwrite=True)

    @staticmethod
    def validate(
            path: Path = _globals.GLOBAL_CFG_FILE,
            root: str = None,
            ensure: list[str] = None,
            deny: list = None
    ) -> bool:
        """
        Validates that required keys exist in the config and are not in a denylist.

        Args:
            path (Path): Path to the config file (default: _globals.GLOBAL_CFG_FILE).
            root (str): Optional top-level section to check (e.g., "auth").
            ensure (list[str]): Keys required to exist. Appended to _ensure_list.
            deny (list): Values considered invalid. Appended to _deny_list.

        Returns:
            bool: True if all keys exist and are valid.

        Raises:
            RuntimeError: If any key is missing or has an invalid value.
        """
        if path is _globals.GLOBAL_CFG_FILE:
            e = _globals.GLOBAL_CFG_ENSURE_LIST + (ensure or [])
        else:
            e = (ensure or [])
        d = _globals.DENY_LIST + (deny or [])
        data = Config.fetch(path=path)

        def resolve(k):
            try:
                section = data[root] if root else data
                for key in section:
                    if key.lower() == k.lower():
                        return section[key]
            except (KeyError, TypeError):
                return None

        for k in e:
            v = resolve(k)
            if v is None:
                print(f"[validate] Missing required config key: {k}")
                raise RuntimeError(f"Missing required config key: {k}")
            if v in d:
                print(f"[validate] Denylisted value for '{k}': {v}")
                raise RuntimeError(f"Denylisted value detected: {k} -> {v}")

        return True

    @staticmethod
    def apply_env(overwrite=True):
        config = Config.dump()
        for k, v in config.items():
            if overwrite or k not in os.environ:
                env.write(k, v)

cfg = Config
