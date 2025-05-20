
class Validation:
    @staticmethod
    def validate_instance(inst):
        """Checks if the incoming instance is valid and not None."""
        if inst is None:
            raise RuntimeError("Instance passed to Config is None.")
        if not hasattr(inst, "__dict__"):
            raise RuntimeError(f"Invalid instance passed to Config: {type(inst).__name__}")

    @staticmethod
    def validate_instance_directory(pdir) -> Path:
        """
        Ensures the instance has a valid `pdir` path.
        Accepts string or Path. Returns Path.
        """
        if isinstance(pdir, str):
            pdir = Path(pdir)
        if not isinstance(pdir, Path):
            raise TypeError("`.pdir` must be a string or pathlib.Path.")
        if not pdir.exists():
            raise FileNotFoundError(f"Directory does not exist: {pdir}")
        return pdir

validate_inst = Validation.validate_instance
validate_inst_dir = Validation.validate_instance_directory

class Parsing:
    @staticmethod
    def traverse_dictionary(data: Any, *keys: Union[str, int], default: Any = None) -> Any:
        """
        Traverse nested dictionaries (and optionally lists) using a list of keys/indexes.

        Parameters:
            data: The initial data structure (dict or list).
            keys: A list of keys or indexes to access nested values.
            default: What to return if any key is not found.

        Returns:
            The final nested value or default if the path doesn't exist.
        """
        current = data
        for key in keys:
            try:
                if isinstance(current, Mapping) and key in current:
                    current = current[key]
                elif isinstance(current, Sequence) and not isinstance(current, str):
                    current = current[key]
                else:
                    return default
            except (KeyError, IndexError, TypeError):
                return default
        return current

traverse_dict = Parsing.traverse_dictionary()

class Setup:
    @staticmethod
    def ensure_project_root(project_path: str | Path) -> Path:
        path, ok = StaticMethods.ensure_path(project_path, is_file=False, create=True)
        if not ok:
            raise OSError(f"Failed to create or access project root: {path}")
        return path

    @staticmethod
    def make_dirs_from_map(base: Path, structure: dict) -> list[Path]:
        """
        Recursively create directories based on a nested dict structure.

        Example:
            structure = {
                "app": {
                    "models": {},
                    "routes": {}
                },
                "config": {},
                "tests": {}
            }
        """
        created = []

        def _create(base_path: Path, tree: dict):
            for name, sub in tree.items():
                dir_path = base_path / name
                dir_path.mkdir(parents=True, exist_ok=True)
                created.append(dir_path)
                _create(dir_path, sub)

        _create(base, structure)
        return created

    @staticmethod
    def write_file(path: Path, content: str, overwrite: bool = False) -> Path:
        if path.exists() and not overwrite:
            return path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    @staticmethod
    def scaffold_project(project_path: str | Path, structure: dict, files: dict[str, str] = None):
        """
        Combines root creation, dir tree, and file writing.

        Args:
            project_path (Path|str): The root path.
            structure (dict): Nested dir structure.
            files (dict[str, str]): Mapping of relative file paths to content strings.
        """
        root = StaticMethods.Setup.ensure_project_root(project_path)
        StaticMethods.Setup.make_dirs_from_map(root, structure)

        if files:
            for rel_path, content in files.items():
                abs_path = root / rel_path
                StaticMethods.Setup.write_file(abs_path, content)

        return root