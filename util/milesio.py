"""
milesio.py

Entry point class for I/O abstractions, consolidating file and path utilities
under a single interface. Includes static nested classes for Path and File
operations. Users should implement the logic inside each method based on their
specific requirements.
"""

import logging
from pathlib import Path
from .io import fileio, pathutil

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class IO:
    """
    Top-level I/O abstraction class. Contains nested static classes for Path and File
    operations to organize I/O-related functionality.
    """

    class Path:
        """
        Namespace for path-related utilities, delegating to PathUtil under the hood.
        """

        @staticmethod
        def normalize(p: str | Path) -> Path:
            """
            Normalize a string or Path-like input to a pathlib.Path object.

            Delegates to PathUtil.normalize_path.

            Args:
                p (str | Path): The path to normalize.

            Returns:
                Path: A normalized pathlib.Path.

            Raises:
                TypeError: If p is not a string or Path.
            """
            logger.debug(f"[IO.Path.normalize] Normalizing path: {p}")
            if not isinstance(p, (str, Path)):
                 raise TypeError(f"Expected str or Path, got {type(p)}")
            return pathutil.normalize_path(p)

        @staticmethod
        def ensure(path: str | Path, *, is_file: bool = False, create: bool = False, verbose: bool = False) -> tuple[Path, bool]:
            """
            Ensure that the given path exists. Optionally create file or directory.

            Delegates to PathUtil.ensure_path.

            Args:
                path (str | Path): Path to validate or create.
                is_file (bool): If True, treat path as a file (create parent directories).
                create (bool): If True, attempt to create the path if it doesn't exist.
                verbose (bool): If True, print messages about created paths or errors.

            Returns:
                tuple[Path, bool]: (Normalized Path, True if existed or was created, False otherwise)

            Raises:
                OSError: If unable to create the path when create=True.
            """
            logger.debug(f"[IO.Path.ensure] Ensuring path: {path} (is_file={is_file}, create={create})")
            if not isinstance(path, (str, Path)):
                 raise TypeError(f"Expected str or Path, got {type(path)}")
            return pathutil.ensure_path(path, is_file=is_file, create=create, verbose=verbose)

        @staticmethod
        def validate_directory(path: str | Path) -> Path:
            """
            Ensure that the given path exists and is a directory. Create if missing.

            Delegates to PathUtil.validate_directory.

            Args:
                path (str | Path): Path to validate or create.

            Returns:
                Path: The validated directory Path.

            Raises:
                OSError: If creation fails.
                NotADirectoryError: If path exists but is not a directory.
            """
            logger.debug(f"[IO.Path.validate_directory] Validating directory: {path}")
            if not isinstance(path, (str, Path)):
                raise TypeError(f"Expected str or Path, got {type(path)}")
            return pathutil.validate_directory(path)

        @staticmethod
        def validate_file(path: str | Path) -> Path:
            """
            Ensure that the given path exists and is a file.

            Delegates to PathUtil.validate_file.

            Args:
                path (str | Path): Path to validate.

            Returns:
                Path: The validated file Path.

            Raises:
                FileNotFoundError: If the file does not exist.
                IsADirectoryError: If the path is a directory instead of a file.
            """
            logger.debug(f"[IO.Path.validate_file] Validating file: {path}")
            if not isinstance(path, (str, Path)):
                 raise TypeError(f"Expected str or Path, got {type(path)}")
            return pathutil.validate_file(path)

    class File:
        """
        Namespace for file-related operations, delegating to FileIO under the hood.
        """

        @staticmethod
        def resolve_extension(path: str | Path) -> str:
            """
            Determine the effective filetype of a given path, including support for dotfiles.

            Delegates to FileIO.resolve_extension.

            Args:
                path (str | Path): Path or filename to evaluate.

            Returns:
                str: Inferred filetype (e.g., 'json', 'env', 'txt').

            Raises:
                ValueError: If the filetype is unsupported or cannot be inferred.
            """
            logger.debug(f"[IO.File.resolve_extension] Resolving extension for: {path}")
            if not isinstance(path, (str, Path)):
                 raise TypeError(f"Expected str or Path, got {type(path)}")
            return fileio.resolve_extension(path)

        @staticmethod
        def read(path: str | Path) -> dict | str:
            """
            Read a configuration or text file based on its extension and return parsed content.

            Delegates to FileIO.read.

            Args:
                path (str | Path): Path to the file.

            Returns:
                dict | str: Parsed file content. TXT returns {'content': str}.

            Raises:
                FileNotFoundError: If the file does not exist.
                ValueError: If extension is unsupported.
                ImportError: If PyYAML is needed but missing.
            """
            logger.debug(f"[IO.File.read] Reading file: {path}")
            if not isinstance(path, (str, Path)):
                 raise TypeError(f"Expected str or Path, got {type(path)}")
            return fileio.read(Path(path))

        @staticmethod
        def write(path: str | Path, data: dict | str, *, overwrite: bool = False, replace_existing: bool = False, section: str = None):
            """
            Write configuration data to a file, optionally merging with existing content.

            Delegates to FileIO.write.

            Args:
                path (str | Path): Target file path.
                data (dict | str): Content to write. Must be a dict or str depending on format.
                overwrite (bool): If True, ignore existing file contents.
                replace_existing (bool): Whether to replace existing keys during merge.
                section (str): For structured formats, write under this section.

            Raises:
                ValueError: For unsupported formats or malformed inputs.
                ImportError: If PyYAML is missing for YAML/YML.
                TypeError: If data is invalid type.
            """
            logger.debug(f"[IO.File.write] Writing to file: {path} (overwrite={overwrite}, replace_existing={replace_existing}, section={section})")
            if not isinstance(path, (str, Path)):
                 raise TypeError(f"Expected str or Path, got {type(path)}")
            if not isinstance(data, (dict, str)):
                raise TypeError(f"Expected dict or str for data, got {type(data)}")
            fileio.write(Path(path), data=data, overwrite=overwrite, replace_existing=replace_existing, section=section)
            pass

        @staticmethod
        def ensure(path: str | Path, default: dict | str, *, encoding: str = "utf-8") -> Path:
            """
            Ensure the file at `path` exists and is non-empty. If not, writes `default` content.

            Delegates to FileIO.ensure_file_with_default.

            Args:
                path (str | Path): Path to the file.
                default (dict | str): Content to write if file is empty or missing.
                encoding (str): File encoding (for plain text).

            Returns:
                Path: The validated file path.

            Raises:
                TypeError: If default type is invalid.
                ValueError: If extension is unsupported.
                OSError: If write fails.
            """
            logger.debug(f"[IO.File.ensure_with_default] Ensuring file with default: {path}")
            if not isinstance(path, (str, Path)):
                 raise TypeError(f"Expected str or Path, got {type(path)}")
            if not isinstance(default, (dict, str)):
               raise TypeError(f"Expected dict or str for default, got {type(default)}")
            return fileio.ensure_file_with_default(Path(path), default=default, encoding=encoding)

path = IO.Path
file = IO.File