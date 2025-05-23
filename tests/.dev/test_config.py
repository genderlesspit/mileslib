import os
from pathlib import Path
from mileslib import StaticMethods as sm
import toml
import json
import yaml

GLOBAL_CFG = Path.cwd / "mileslib_settings.toml"
GLOBAL_CFG_DEFAULT = {

}
PROJECT_CFG_DEFAULT = {

}

class Config:
    """
    Flexible configuration manager supporting multi-format file loading and structured key access.

    Loads configuration from TOML, JSON, or YAML files and provides deep key retrieval,
    validation, and mergeable write-back functionality.

    File format is auto-detected based on file extension.
    """

    @staticmethod
    def build(path):
        default = None
        file = None
        try:
            if path is GLOBAL_CFG:
                default = GLOBAL_CFG_DEFAULT
                file = sm.ensure_file_with_default(path, default)
            else:
                file, created = sm.ensure_path(path, is_file=True, create=True)
        except Exception as e:
            raise RuntimeError(f"Could not build config!: {e}")
        if file is not None: return file
        raise FileNotFoundError

    @staticmethod
    def dump(path: Path = GLOBAL_CFG) -> dict:
        """
        Prints the current config file as formatted JSON for inspection.

        Useful for CLI diagnostics or debugging.

        Args:
            path (Path): Project directory.
            file_name (str): Specific config file to print (default: auto-detect).
        """
        file = path
        if not sm.check_input(path, expected=Path): raise FileNotFoundError

        file_ext = file.suffix.lower().lstrip(".")
        valid_ext = ["toml", "json", "yaml", "yml"]

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

        def check_ext(ext: str) -> str:
            if ext not in valid_ext:
                raise TypeError
            return ext

        def get_parser(ext: str) -> dict:
            try:
                ext = check_ext(ext)
                if ext not in parsers: raise TypeError
                parser = parsers[ext]
                return parser(file)
            except Exception:
                raise RuntimeError

        parsed_data = get_parser(file_ext)

        if not isinstance(parsed_data, dict): raise TypeError
        return parsed_data

    @staticmethod
    def load(path: Path = GLOBAL_CFG) -> dict:
        loaded_cfg = sm.recall(
            lambda: Config.build(path),  # <- primary attempt
            lambda: Config.dump(path)  # <- fallback / fix
        )
        return loaded_cfg

    @staticmethod
    def get(*keys, path: Path = None, default: Any = None, expected: Any = None,
            is_global: bool = False, section: str = None) -> Any:
        """
        Retrieves a nested configuration value from the loaded file.

        Supports chained key access (e.g., cfg.get("profile", "version")) and optional value assertion.

        Args:
            *keys: One or more keys to traverse the configuration hierarchy.
            path (Path): Project root directory.
            default (Any): Value to return if key path is not found.
            expected (Any): If provided, raises ValueError if the retrieved value != expected.
            is_global (bool): If True, loads only global config files.
            section (str): Root section to search within before resolving nested keys.

        Returns:
            Any: The resolved value or default.

        Raises:
            RuntimeError: On key error, format mismatch, or assertion failure.
        """

    @staticmethod
    def write(data: dict, *, path: Path = None, file_name: str = "settings.toml",
              overwrite: bool = False, replace_existing: bool = False, section: str = None) -> None:
        """
        Writes configuration data to disk using FileIO.

        Merges with existing config unless overwrite=True. If section is provided, writes only
        to that subsection (e.g., "profile.editor").

        Args:
            data (dict): Configuration data to write.
            path (Path): Project root directory.
            file_name (str): Target file name to write.
            overwrite (bool): If True, overwrites the entire file.
            replace_existing (bool): If True, overwrites existing keys when merging.
            section (str): Optional dot-path to write data into a nested section.

        Returns:
            None
        """

    @staticmethod
    def validate(keys: list[str], root: str = None, denylist: list = None, path: Path = None) -> bool:
        """
        Validates that the required keys exist and are not denylisted.

        Traverses a root section and verifies key presence and value constraints.

        Args:
            keys (list[str]): Required keys to check.
            root (str): Optional top-level section to start from.
            denylist (list, optional): Values considered invalid.
            path (Path): Project root directory.

        Returns:
            bool: True if all keys pass validation.

        Raises:
            RuntimeError: If required keys are missing or invalid.
        """