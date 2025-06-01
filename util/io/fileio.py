import json
from pathlib import Path
import yaml
import toml

class FileIO:
    """
    Static methods for reading and writing configuration files in multiple formats.
    Supports: TOML, JSON, ENV, YAML, YML, TXT.

    Files are merged if they exist and overwrite is False.
    """
    SUPPORTED_FORMATS = ["txt", "toml", "json", "env", "yml", "yaml"]
    DOTFILE_MAP = {
        ".env": "env",
        ".gitignore": "txt",
        ".dockerignore": "txt",
        ".editorconfig": "ini",
    }

    @staticmethod
    def resolve_extension(path: str | Path) -> str:
        """
        Determines the effective filetype of a given path, including support for dotfiles.

        Args:
            path (str | Path): Path or filename to evaluate.

        Returns:
            str: Inferred filetype (e.g., 'json', 'env', 'txt').

        Raises:
            ValueError: If the filetype is unsupported or cannot be inferred.
        """
        path = Path(path)
        suffix = path.suffix.lstrip(".").lower()
        name = path.name.lower()

        dotfile_map = FileIO.DOTFILE_MAP
        supported = FileIO.SUPPORTED_FORMATS + list(dotfile_map.values())

        if suffix and suffix in supported:
            return suffix

        if name in dotfile_map:
            return dotfile_map[name]

        raise ValueError(f"[FileIO] Unsupported or unknown filetype for path: {path}")

    @staticmethod
    def read(path: Path) -> dict | str:
        """
        Reads a configuration file based on its extension and returns parsed content.

        Args:
            path (Path): Path to the file.

        Returns:
            dict | str: Parsed configuration content. TXT returns {'content': str}.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If file extension is unsupported.
            ImportError: If PyYAML is needed but not installed.
        """
        if not path.exists():
            raise FileNotFoundError(f"[FileIO.read] File not found: {path}")

        ext = FileIO.resolve_extension(path)

        if ext == "toml":
            import toml
            return toml.load(path)

        elif ext == "json":
            return json.loads(path.read_text(encoding="utf-8"))

        elif ext == "env":
            content = {}
            for line in path.read_text().splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.split("=", 1)
                    content[k.strip()] = v.strip().strip('"')
            return content

        elif ext in ("yaml", "yml"):
            try:
                import yaml
            except ImportError:
                raise ImportError("Install PyYAML to use YAML/YML support.")
            return yaml.safe_load(path.read_text())

        elif ext == "txt":
            return {"content": path.read_text(encoding="utf-8")}

        else:
            raise ValueError(f"[FileIO.read] Unsupported format: {ext}")

    @staticmethod
    def write(
            path: Path,
            data: dict | str,
            overwrite: bool = False,
            replace_existing: bool = False,
            section: str = None
    ):
        """
        Writes configuration data to a file, optionally merging with existing contents.
        Accepts both dict and str. All formats go through centralized logic.

        Args:
            path (Path): Target file path.
            data (dict | str): Content to write. Must be a dict or str depending on format.
            overwrite (bool): If True, ignore existing file contents.
            replace_existing (bool): Whether to replace existing keys during merge.
            section (str): For structured formats, write under this section if provided.

        Raises:
            ValueError: For unsupported formats or malformed inputs.
            ImportError: If PyYAML is missing for .yml/.yaml.
        """
        ext = FileIO.resolve_extension(path)

        if ext not in FileIO.SUPPORTED_FORMATS:
            raise ValueError(f"[FileIO] Unsupported file extension: .{ext}")

        path.parent.mkdir(parents=True, exist_ok=True)

        # Normalize string input
        if isinstance(data, str):
            if ext == "txt":
                data = {"content": data}
            elif ext == "env":
                lines = data.strip().splitlines()
                data = {
                    k.strip(): v.strip().strip('"')
                    for k, v in (line.split("=", 1) for line in lines if "=" in line)
                }
            elif ext in ("toml", "json", "yaml", "yml"):
                try:
                    data = json.loads(data)
                    if not isinstance(data, dict):
                        raise ValueError(f"[FileIO] String must serialize to dict for .{ext}")
                except json.JSONDecodeError as e:
                    raise ValueError(f"[FileIO] String content for .{ext} must be valid JSON: {e}")
            else:
                raise ValueError(f"[FileIO] Cannot use str input with unsupported format: .{ext}")

        if not isinstance(data, dict):
            raise TypeError(f"[FileIO] Final data must be a dict for .{ext}, got {type(data)}")

        merged_data = {}

        if not overwrite and path.exists():
            existing = FileIO.read(path)

            if ext in ("toml", "json", "yaml", "yml"):
                if section:
                    base = existing.get(section, {})
                    merged = FileIO._merge(base, data, replace_existing)
                    existing[section] = merged
                    merged_data = existing
                else:
                    merged_data = FileIO._merge(existing, data, replace_existing)
            else:
                merged_data = FileIO._merge(existing, data, replace_existing)
        else:
            if ext in ("toml", "json", "yaml", "yml"):
                merged_data = {section: data} if section else data
            else:
                merged_data = data

        # Write to disk
        if ext == "toml":
            import toml
            path.write_text(toml.dumps(merged_data), encoding="utf-8")
        elif ext == "json":
            path.write_text(json.dumps(merged_data, indent=2), encoding="utf-8")
        elif ext == "env":
            with path.open("w", encoding="utf-8") as f:
                for k, v in merged_data.items():
                    f.write(f'{k}="{v}"\n')
        elif ext in ("yaml", "yml"):
            try:
                import yaml
            except ImportError:
                raise ImportError("Install PyYAML to use YAML/YML support.")
            with path.open("w", encoding="utf-8") as f:
                yaml.safe_dump(merged_data, f)
        elif ext == "txt":
            if not isinstance(merged_data, dict) or "content" not in merged_data:
                raise ValueError("TXT write requires {'content': str}")
            path.write_text(merged_data["content"], encoding="utf-8")

    @staticmethod
    def _merge(base: dict, new: dict, replace: bool = False) -> dict:
        """
        Merges two dictionaries with optional key replacement.

        Args:
            base (dict): Original dictionary to merge into.
            new (dict): New dictionary to merge.
            replace (bool): Whether to replace existing keys.

        Returns:
            dict: Merged result.
        """
        merged = base.copy()
        for k, v in new.items():
            if k not in merged or replace:
                merged[k] = v
        return merged

    @staticmethod
    def ensure_file_with_default(
            path: str | Path,
            default: dict | str,
            encoding: str = "utf-8"
    ) -> Path:
        """
        Ensures the file at `path` exists and is non-empty. If not, writes `default` content.
        Supports toml, json, yaml/yml, env, and txt formats.

        Args:
            path (str | Path): Path to the file.
            default (dict | str): Content to write if file is empty or missing.
            encoding (str): File encoding (for plain text).

        Returns:
            Path: Validated path.

        Raises:
            TypeError: If default type is invalid.
            ValueError: If extension unsupported.
            OSError: If write fails.
        """
        path = Path(path)
        ext = FileIO.resolve_extension(path)

        if ext not in FileIO.SUPPORTED_FORMATS:
            raise ValueError(f"[FileIO] Unsupported file extension: .{ext}")

        if path.exists():
            if ext in ["txt", "env"] and path.read_text(encoding=encoding).strip() == "":
                print(f"[FileIO] {path} exists but is empty, overwriting...")
            elif path.stat().st_size > 0:
                print(f"[FileIO] {path} already exists and is non-empty, skipping write.")
                return path
        else:
            print(f"[FileIO] {path} does not exist. Will create it.")

        path.parent.mkdir(parents=True, exist_ok=True)

        try:
            # Write dicts
            if isinstance(default, dict):
                for k, v in default.items():
                    if v is None:
                        default[k] = ""
                print(f"[FileIO] Writing dict to {path}:\n{json.dumps(default, indent=2)}")
                if ext == "env":
                    default = {k: str(v) for k, v in default.items()}
                    FileIO.write(path, data=default, overwrite=True)
                elif ext == "toml":
                    path.write_text(toml.dumps(default), encoding=encoding)
                elif ext == "json":
                    path.write_text(json.dumps(default, indent=2), encoding=encoding)
                elif ext in ("yaml", "yml"):
                    path.write_text(yaml.safe_dump(default, sort_keys=False), encoding=encoding)
                elif ext == "txt":
                    path.write_text(str(default), encoding=encoding)
                else:
                    raise ValueError(f"[FileIO] Cannot write dict to unknown format: {ext}")

            # Write strings
            elif isinstance(default, str):
                if ext == "txt":
                    print(f"[FileIO] Writing plain text to {path}:\n{default}")
                    path.write_text(default, encoding=encoding)
                elif ext == "env":
                    lines = default.strip().splitlines()
                    env_dict = {
                        k.strip(): v.strip().strip('"')
                        for k, v in (line.split("=", 1) for line in lines if "=" in line)
                    }
                    print(f"[FileIO] Writing parsed ENV string to {path}:\n{json.dumps(env_dict, indent=2)}")
                    FileIO.write(path, data=env_dict, overwrite=True)
                else:
                    print(f"[FileIO] Writing raw string to {path}:\n{default}")
                    path.write_text(default, encoding=encoding)

            else:
                raise TypeError("[FileIO] Default must be a dict or str.")

            print(f"[FileIO] Successfully wrote default content to {path}")

        except Exception as e:
            raise OSError(f"[FileIO] Failed to write to '{path}': {e}")

        return path

read = FileIO.read
write = FileIO.write
ensure_file_with_default = FileIO.ensure_file_with_default
resolve_extension = FileIO.resolve_extension