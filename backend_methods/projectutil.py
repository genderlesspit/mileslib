from pathlib import Path

from util import milesutil as mu
from context import milescontext as mc

class ProjectUtils:
    """
    Utilities for managing and validating selected MilesLib project context.
    """

    @staticmethod
    def select_project(name: str, path: Path) -> Path:
        """
        Sets the selected MilesLib project by name or path into the global environment config.

        Args:
            name (str): The project name (directory name).
            path (Path): The full path to the project directory.

        Returns:
            Path: The resolved project path.

        Raises:
            TypeError: If name or path are not strings after normalization.
        """
        ensured_path = mu.Path.validate_directory(path)
        str_path = str(ensured_path)
        args = [name, str_path]
        mu.check_types(args, str)  # Defensive: ensure all inputs are strings

        mc.env.write("selected_project_name", str_path, replace_existing=True)
        mc.env.write("selected_project_path", str_path, replace_existing=True)
        print(f"[select_project] Active project path set: {str_path}")
        return ensured_path

    @staticmethod
    def discover_projects(root: Path = mc.gvar.GLOBAL_ROOT) -> list[tuple[str, Path]]:
        """
        Scans root for valid MilesLib projects with config files.

        Returns:
            List of tuples: (project_name, project_path)
        """
        found = []
        for sub in root.iterdir():
            if not sub.is_dir() or sub.name.startswith("__") or "pycache" in sub.name.lower():
                continue
            cfg = sub / f"mileslib_{sub.name}_settings.toml"
            if cfg.exists():
                found.append((sub.name, sub.resolve()))
        return found

    @staticmethod
    def db_name(project: str) -> str:
        """
        Resolves and returns the database name for the project.
        If it does not exist, creates a default database name.

        Args:
            project (str): Project name

        Returns:
            str: Resolved or generated database name
        """
        db_name = mc.env.get(f"{project}.DB_NAME", required=False) or f"{project.lower()}-pg"
        mc.env.write(f"{project}.DB_NAME", db_name, replace_existing=True)
        return db_name
