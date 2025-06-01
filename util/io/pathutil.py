from pathlib import Path

class PathUtil:
    @staticmethod
    def normalize_path(p: str | Path) -> Path:
        """
        Normalize a string or Path-like input to a pathlib.Path object.

        Args:
            p (str | Path): Input path to normalize.

        Returns:
            Path: A pathlib-compatible Path object.
        """
        return Path(p)

    @staticmethod
    def get_mileslib_root() -> Path:
        """
        Get the root path of the installed mileslib package.

        Returns:
            Path: The absolute directory path where mileslib is located.
        """
        return Path(__file__).resolve().parent

    @staticmethod
    def ensure_path(
            path: str | Path,
            is_file: bool = False,
            create: bool = False,
            verbose: bool = False
    ) -> tuple[Path, bool]:
        """
        Ensure that a file or directory exists at the given path.

        Args:
            path (str | Path): The path to validate or create.
            is_file (bool): If True, treat path as a file (creates parent directory).
            create (bool): If True, attempt to create the path if it doesn't exist.
            verbose (bool): If True, print messages about created paths or errors.

        Returns:
            tuple[Path, bool]: A tuple with the normalized path and a bool indicating if it existed or was created.
        """
        path = Path(path)

        if path.exists():
            return path, True

        if not create:
            return path, False

        try:
            if is_file:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch(exist_ok=True)
                if verbose:
                    print(f"[Created File] {path}")
            else:
                path.mkdir(parents=True, exist_ok=True)
                if verbose:
                    print(f"[Created Directory] {path}")
            return path, True
        except Exception as e:
            if verbose:
                print(f"[Error Creating Path] {e}")
            return path, False

    @staticmethod
    def validate_directory(path: str | Path) -> Path:
        """
        Ensure that the given path exists and is a directory.

        Args:
            path (str | Path): Path to validate or create.

        Returns:
            Path: The validated directory path.

        Raises:
            OSError: If the directory cannot be created.
            NotADirectoryError: If the path exists but is not a directory.
        """
        path = Path(path)
        if not path.exists():
            try:
                path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                raise OSError(f"Failed to create directory '{path}': {e}")
        elif not path.is_dir():
            raise NotADirectoryError(f"'{path}' exists but is not a directory.")
        return path

    @staticmethod
    def validate_file(path: str | Path) -> Path:
        """
        Ensure that the given path exists and is a file.

        Args:
            path (str | Path): Path to validate.

        Returns:
            Path: The validated file path.

        Raises:
            FileNotFoundError: If the file does not exist.
            IsADirectoryError: If the path is a directory instead of a file.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: '{path}'")
        if path.is_dir():
            raise IsADirectoryError(f"Expected a file but found a directory at: '{path}'")
        return path

root = PathUtil.get_mileslib_root
normalize_path = PathUtil.normalize_path
ensure_path = PathUtil.ensure_path
validate_directory = PathUtil.validate_directory
validate_file = PathUtil.validate_file
PATH_USAGE = """
StaticMethods PathUtil Aliases
------------------------------

These utility functions wrap common file and path operations:

root() -> Path
    Returns the root path of the installed mileslib package.
    Useful for locating bundled templates or defaults.

normalize_path(p: str | Path) -> Path
    Normalize a string or Path-like object to a pathlib.Path.

ensure_path(path, is_file=False, create=False, verbose=False) -> tuple[Path, bool]
    Ensure a file or directory exists. Optionally creates it.
    Returns the normalized path and a bool indicating existence or creation.

ensure_file_with_default(path, default: dict | str, encoding="utf-8") -> Path
    Ensure a file exists and is populated. Writes JSON or text if missing or empty.

validate_directory(path: str | Path) -> Path
    Ensure the path exists and is a directory. Raises errors if invalid.

validate_file(path: str | Path) -> Path
    Ensure the path exists and is a file. Raises errors if invalid or missing.
"""