from pathlib import Path

class StaticMethods: # For Internal Use
    @staticmethod
    def _validate_instance(inst):
        """Checks if the incoming instance is valid and not None."""
        if inst is None:
            raise RuntimeError("Instance passed to Config is None.")
        if not hasattr(inst, "__dict__"):
            raise RuntimeError(f"Invalid instance passed to Config: {type(inst).__name__}")


    @staticmethod
    def _validate_instance_directory(pdir) -> str:
        """
        Ensures the instance has a valid `pdir` path.
        Returns the path if valid, else raises a clear error.
        """
        if not isinstance(pdir, Path):
            raise TypeError("`.pdir` must be a Path.")
        if not os.path.exists(pdir):
            raise FileNotFoundError(f"Project directory does not exist: {pdir}")
        return pdir


    @staticmethod
    def _validate_directory(path: str | Path) -> Path:
        """
        Ensures the provided directory exists. Attempts to create it if missing.

        Args:
            path (str | Path): The path to validate.

        Returns:
            Path: The validated directory path as a Path object.

        Raises:
            OSError: If directory creation fails.
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
    def _validate_file(path: str | Path) -> Path:
        """
        Ensures the provided file exists.

        Args:
            path (str | Path): The path to the file to check.

        Returns:
            Path: The validated file path as a Path object.

        Raises:
            FileNotFoundError: If the file does not exist.
            IsADirectoryError: If the path exists but is a directory.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: '{path}'")
        if path.is_dir():
            raise IsADirectoryError(f"Expected a file but found a directory at: '{path}'")
        return path


    @staticmethod
    def _ensure_file_with_default(
            path: str | Path,
            default: dict | str,
            encoding: str = "utf-8"
    ) -> Path:
        """
        Ensures a file exists at the given path. If not, creates it with default content.

        Args:
            path (str | Path): The path to the file.
            default (dict | str): The default content to write if file is missing.
                - If dict, will be written as JSON.
                - If str, written as plain text.
            encoding (str): Encoding used when writing the file (default is utf-8).

        Returns:
            Path: The path to the existing or newly created file.

        Raises:
            TypeError: If default is not a dict or str.
            OSError: If writing the file fails.
        """
        path = Path(path)
        if not path.exists():
            try:
                path.parent.mkdir(parents=True, exist_ok=True)

                with open(path, "w", encoding=encoding) as f:
                    if isinstance(default, dict):
                        json.dump(default, f, indent=4)
                    elif isinstance(default, str):
                        f.write(default)
                    else:
                        raise TypeError("Default content must be a dict (for JSON) or a str.")
            except Exception as e:
                raise OSError(f"Failed to create file at '{path}': {e}")
        return path