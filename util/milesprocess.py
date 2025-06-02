import importlib.util
import logging
import subprocess
import sys
from pathlib import Path
from typing import Union, Optional, Dict

from util.milessubprocess.cmd import CMD
from util.milessubprocess.external_dependency import ExternalDependency

logger = logging.getLogger(__name__)


class MilesProcess:
    class Runner:
        @staticmethod
        def run(
            cmd: Union[str, list],
            *,
            shell: bool = False,
            capture_output: bool = True,
            check: bool = True,
            text: bool = True,
            env: Optional[Dict[str, str]] = None,
            force_global_shell: bool = False,
            cwd: Optional[Union[str, Path]] = None,
        ) -> subprocess.CompletedProcess:
            """
            Execute a command via CMD.run() with logging and type checks.

            Args:
                cmd: Command string or list.
                shell: Whether to run in shell mode.
                capture_output: Capture stdout/stderr.
                check: If True, raise CalledProcessError on non-zero exit.
                text: If True, decode output to string.
                env: Custom environment variables.
                force_global_shell: Force CMD to treat this as a global shell invocation on Windows.
                cwd: Working directory for the subprocess.

            Returns:
                CompletedProcess instance on success.

            Raises:
                TypeError: If argument types are invalid.
                CalledProcessError: If the subprocess exits with non-zero (when check=True).
            """
            # --- Type checks ---
            if not isinstance(cmd, (str, list)):
                raise TypeError(f"[Runner.run] 'cmd' must be str or list, got {type(cmd).__name__}")
            if env is not None and not isinstance(env, dict):
                raise TypeError(f"[Runner.run] 'env' must be dict or None, got {type(env).__name__}")
            if cwd is not None and not isinstance(cwd, (str, Path)):
                raise TypeError(f"[Runner.run] 'cwd' must be str, pathlib.Path, or None, got {type(cwd).__name__}")

            # Convert Path to str for CMD.run
            cwd_str: Optional[str]
            if isinstance(cwd, Path):
                cwd_str = str(cwd)
            else:
                cwd_str = cwd

            # Log invocation at INFO level (minimal details)
            logger.info("Executing command: %r (cwd=%r)", cmd, cwd_str)

            try:
                result = CMD.run(
                    cmd,
                    shell=shell,
                    capture_output=capture_output,
                    check=check,
                    text=text,
                    env=env,
                    force_global_shell=force_global_shell,
                    cwd=cwd_str,
                )
                # Log success only if returncode == 0
                if result.returncode == 0:
                    logger.info("Command succeeded (returncode=0)")
                else:
                    # This block is only reached if check=False
                    logger.warning("Command completed with non-zero exit (returncode=%d)", result.returncode)
                return result

            except subprocess.CalledProcessError as exc:
                # Detailed failure logging at ERROR level
                logger.error(
                    "Command failed (returncode=%d). cmd=%r%s",
                    exc.returncode,
                    cmd,
                    f", stderr={exc.stderr!r}" if exc.stderr else ""
                )
                raise

    class Dependency:
        @staticmethod
        def in_venv() -> bool:
            """
            Return True if running inside a virtual environment.
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
            Ensure that a given external tool is installed (or install it).

            Args:
                tool: Name of the tool to install/verify.

            Raises:
                TypeError: If 'tool' is not a string.
                ValueError: If the tool is unknown.
                RuntimeError: If installation or post-check fails.
            """
            if not isinstance(tool, str):
                raise TypeError(f"[Dependency.ensure] 'tool' must be a string, got {type(tool).__name__}")
            logger.info("Ensuring external dependency: %s", tool)
            try:
                ExternalDependency.ensure(tool)
                logger.debug("Dependency.ensure succeeded for tool=%r", tool)
            except ValueError as ve:
                logger.error("Dependency.ensure: Unknown tool %r: %s", tool, ve)
                raise
            except RuntimeError as re:
                logger.error("Dependency.ensure: Installation or post-check failed for %r: %s", tool, re)
                raise

        @staticmethod
        def ensure_all() -> None:
            """
            Ensure that all required external dependencies are installed.
            """
            logger.info("Ensuring all external dependencies")
            logger.debug("Dependency.ensure_all called")
            try:
                ExternalDependency.ensure_all()
                logger.debug("Dependency.ensure_all completed successfully")
            except Exception as exc:
                logger.error("Dependency.ensure_all encountered error: %s", exc)
                raise

    class PythonDependencies:
        @staticmethod
        def _dependency(dep: str, pack: Optional[str] = None) -> bool:
            """
            Internal helper to install a Python package if not already present.

            Args:
                dep: Python module name to check.
                pack: Package name to pip-install (if different from module name).

            Returns:
                True if the module is present or installation succeeded; False otherwise.

            Raises:
                TypeError: If arguments have the wrong type.
            """
            if not isinstance(dep, str):
                raise TypeError(f"[PythonDependencies._dependency] 'dep' must be a string, got {type(dep).__name__}")
            if pack is not None and not isinstance(pack, str):
                raise TypeError(f"[PythonDependencies._dependency] 'pack' must be a string if provided, got {type(pack).__name__}")

            if importlib.util.find_spec(dep) is not None:
                logger.debug("PythonDependencies._dependency: '%s' already installed", dep)
                return True

            pkg_name = pack or dep
            logger.info("Installing Python package: %s", pkg_name)
            try:
                completed = CMD.pip_install(pkg_name)
                if completed.returncode == 0:
                    logger.debug("PythonDependencies._dependency: installation succeeded for '%s'", pkg_name)
                    return True
                else:
                    logger.error(
                        "PythonDependencies._dependency: pip_install returned non-zero code (%d) for '%s'",
                        completed.returncode, pkg_name
                    )
                    return False
            except subprocess.CalledProcessError as exc:
                logger.error("PythonDependencies._dependency: pip_install raised CalledProcessError for '%s': %s", pkg_name, exc)
                return False

        @staticmethod
        def try_import(package: str):
            """
            Attempt to import a Python module; if missing, pip-install and re-import.

            Args:
                package: Module name to import/install.

            Returns:
                The imported module object.

            Raises:
                TypeError: If 'package' is not a string.
                RuntimeError: If installation fails or import still fails.
            """
            if not isinstance(package, str):
                raise TypeError(f"[PythonDependencies.try_import] 'package' must be a string, got {type(package).__name__}")

            logger.info("Attempting to import Python module: %s", package)
            try:
                return importlib.import_module(package)
            except ImportError:
                logger.info("Module '%s' not found; attempting to install.", package)
                success = MilesProcess.PythonDependencies._dependency(package)
                if not success:
                    raise RuntimeError(f"Failed to install package: {package}")

                try:
                    module = importlib.import_module(package)
                    logger.debug("PythonDependencies.try_import: successfully imported '%s' after install", package)
                    return module
                except ImportError as e:
                    logger.error(
                        "PythonDependencies.try_import: import still failed after installing '%s': %s",
                        package, e
                    )
                    raise RuntimeError(f"Module '{package}' could not be imported even after installation.") from e

# Convenience aliases
run = MilesProcess.Runner.run
ensure_dependency = MilesProcess.Dependency.ensure
ensure_all_dependencies = MilesProcess.Dependency.ensure_all
in_virtualenv = MilesProcess.Dependency.in_venv
try_import = MilesProcess.PythonDependencies.try_import
