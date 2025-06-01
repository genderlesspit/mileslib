import importlib.util
import logging
import subprocess
import sys

# Import your existing CMD and ExternalDependency
from util.subprocess.cmd import CMD
from util.subprocess.external_dependency import ExternalDependency

# ─── Native Python Logger ────────────────────────────────────────────
# Retrieve a module‐level logger. Do NOT add handlers here; let the application configure it.
logger = logging.getLogger(__name__)

class MilesProcess:
    """
    Entry point for MilesLib process utilities.
    Provides two nested subclasses:
      - Runner: wraps subprocess execution via CMD
      - Dependency: wraps ExternalDependency for installing/checking tools
    """

    class Runner:
        """
        Subclass providing subprocess execution utilities.
        Delegates directly to CMD.run(), but adds logging and type checks.
        """

        @staticmethod
        def run(
            cmd: str | list,
            *,
            shell: bool = False,
            capture_output: bool = True,
            check: bool = True,
            text: bool = True,
            env: dict | None = None,
            force_global_shell: bool = False
        ) -> subprocess.CompletedProcess:
            """
            Execute a command via subprocess.CMD.run() with basic logging.

            Args:
                cmd (str | list): Command string or list of args.
                shell (bool): Whether to execute through the shell.
                capture_output (bool): Capture stdout/stderr.
                check (bool): Raise CalledProcessError on non-zero exit.
                text (bool): Return strings rather than bytes.
                env (dict | None): Environment variables for the command.
                force_global_shell (bool): On Windows, force-wrap in `cmd.exe /c`.

            Returns:
                subprocess.CompletedProcess: The result from subprocess.
            """
            # Defensive type checks
            if not isinstance(cmd, (str, list)):
                raise TypeError(f"[Runner.run] 'cmd' must be str or list, got {type(cmd).__name__}")
            if env is not None and not isinstance(env, dict):
                raise TypeError(f"[Runner.run] 'env' must be dict or None, got {type(env).__name__}")

            logger.debug(
                "Runner.run called with cmd=%r, shell=%s, capture_output=%s, check=%s, text=%s, "
                "env_keys=%s, force_global_shell=%s",
                cmd, shell, capture_output, check, text,
                list(env.keys()) if env else None, force_global_shell
            )

            try:
                result = CMD.run(
                    cmd,
                    shell=shell,
                    capture_output=capture_output,
                    check=check,
                    text=text,
                    env=env,
                    force_global_shell=force_global_shell
                )
                logger.debug("Runner.run completed: returncode=%d", result.returncode)
                return result
            except subprocess.CalledProcessError as exc:
                logger.error("Runner.run failed: %s", exc)
                raise

    class Dependency:
        """
        Subclass providing external dependency management utilities.
        Delegates to ExternalDependency, but wraps with logging and minimal checks.
        """

        @staticmethod
        def in_venv() -> bool:
            """
            Check if current Python process is inside a virtual environment.

            Returns:
                bool: True if in a venv, False otherwise.
            """
            logger.debug("Dependency.in_venv called")
            try:
                return ExternalDependency.in_venv()
            except Exception as exc:
                logger.error("Dependency.in_venv encountered error: %s", exc)
                raise

        @staticmethod
        def ensure(tool: str) -> None:
            """
            Ensure that a given external tool is installed. If missing, attempt to install.

            Args:
                tool (str): Name of the tool (e.g., 'azure', 'docker', 'rust').

            Raises:
                TypeError: If 'tool' is not a string.
                ValueError: If 'tool' is not recognized.
                RuntimeError: If installation or post-check fails.
            """
            if not isinstance(tool, str):
                raise TypeError(f"[Dependency.ensure] 'tool' must be a string, got {type(tool).__name__}")

            logger.debug("Dependency.ensure called for tool=%r", tool)
            try:
                ExternalDependency.ensure(tool)
                logger.debug("Dependency.ensure succeeded for tool=%r", tool)
            except ValueError as ve:
                logger.error("Dependency.ensure: Unknown tool %r: %s", tool, ve)
                raise
            except RuntimeError as re:
                logger.error("Dependency.ensure: Installation/post-check failed for %r: %s", tool, re)
                raise

        @staticmethod
        def ensure_all() -> None:
            """
            Ensure that all configured external tools (per INSTALLERS) are installed.
            """
            logger.debug("Dependency.ensure_all called")
            try:
                ExternalDependency.ensure_all()
                logger.debug("Dependency.ensure_all completed successfully")
            except Exception as exc:
                logger.error("Dependency.ensure_all encountered error: %s", exc)
                raise
    class PythonDependencies:
        """
        Provides utilities for Python‐package dependencies (pip‐based).
        - _dependency: installs a package using CMD.pip_install if not already present.
        - try_import: attempts import; if missing, installs via pip and retries once.
        """

        @staticmethod
        def _dependency(dep: str, pack: str = None) -> bool:
            """
            Ensure that a Python module is installed. If not present, run `pip install` via CMD.

            Args:
                dep (str): The name of the importable module (e.g., 'requests').
                pack (str): Optional pip package name if it differs from the module name.

            Returns:
                bool: True if the module is present or installation succeeded; False otherwise.

            Raises:
                TypeError: If `dep` or `pack` (when provided) is not a string.
            """
            if not isinstance(dep, str):
                raise TypeError(f"[PythonDependencies._dependency] 'dep' must be a string, got {type(dep).__name__}")
            if pack is not None and not isinstance(pack, str):
                raise TypeError(f"[PythonDependencies._dependency] 'pack' must be a string if provided, got {type(pack).__name__}")

            # Check if module is already importable
            if importlib.util.find_spec(dep) is not None:
                logger.debug("PythonDependencies._dependency: module '%s' already installed", dep)
                return True

            pkg_name = pack or dep
            logger.info("PythonDependencies._dependency: installing package '%s' via CMD.pip_install", pkg_name)
            try:
                # Delegates to CMD.pip_install; this returns CompletedProcess or raises CalledProcessError
                completed = CMD.pip_install(pkg_name)
                if completed.returncode == 0:
                    logger.debug("PythonDependencies._dependency: installation succeeded for '%s'", pkg_name)
                    return True
                else:
                    logger.error("PythonDependencies._dependency: pip_install returned non-zero code for '%s': %d",
                                 pkg_name, completed.returncode)
                    return False
            except subprocess.CalledProcessError as exc:
                logger.error("PythonDependencies._dependency: pip_install failed for '%s': %s", pkg_name, exc)
                return False

        @staticmethod
        def try_import(package: str):
            """
            Attempt to import a Python package by name. If missing, try to install via CMD.pip_install,
            then retry the import once. Raises RuntimeError if import still fails.

            Args:
                package (str): Name of the package to import (e.g., 'numpy').

            Returns:
                module: The imported module object.

            Raises:
                TypeError: If `package` is not a string.
                RuntimeError: If installation fails or module cannot be imported after install.
            """
            if not isinstance(package, str):
                raise TypeError(f"[PythonDependencies.try_import] 'package' must be a string, got {type(package).__name__}")

            logger.debug("PythonDependencies.try_import: attempting import of '%s'", package)
            try:
                return importlib.import_module(package)
            except ImportError:
                logger.info("PythonDependencies.try_import: '%s' not found. Attempting installation via CMD.pip_install.", package)
                success = MilesProcess.PythonDependencies._dependency(package)
                if not success:
                    raise RuntimeError(f"Failed to install package: {package}")

                # Retry import exactly once
                try:
                    module = importlib.import_module(package)
                    logger.debug("PythonDependencies.try_import: successfully imported '%s' after install", package)
                    return module
                except ImportError as e:
                    logger.error(
                        "PythonDependencies.try_import: import failed after installation for '%s': %s",
                        package, e
                    )
                    raise RuntimeError(f"Module '{package}' could not be imported even after installation.") from e

# ─── Convenience Aliases ───────────────────────────────────────────────
run = MilesProcess.Runner.run
ensure_dependency = MilesProcess.Dependency.ensure
ensure_all_dependencies = MilesProcess.Dependency.ensure_all
in_virtualenv = MilesProcess.Dependency.in_venv
try_import = MilesProcess.PythonDependencies.try_import