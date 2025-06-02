# milesprocess.py

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
            We no longer double-wrap .cmd/.bat on Windows—CMD.run() handles it.
            """
            if not isinstance(cmd, (str, list)):
                raise TypeError(f"[Runner.run] 'cmd' must be str or list, got {type(cmd).__name__}")
            if env is not None and not isinstance(env, dict):
                raise TypeError(f"[Runner.run] 'env' must be dict or None, got {type(env).__name__}")
            if cwd is not None and not isinstance(cwd, (str, Path)):
                raise TypeError(f"[Runner.run] 'cwd' must be str, pathlib.Path, or None, got {type(cwd).__name__}")

            cwd_str: Optional[str]
            if isinstance(cwd, Path):
                cwd_str = str(cwd)
            else:
                cwd_str = cwd

            logger.debug(
                "Runner.run called with cmd=%r, shell=%s, capture_output=%s, check=%s, text=%s, "
                "env_keys=%s, force_global_shell=%s, cwd=%r",
                cmd, shell, capture_output, check, text,
                list(env.keys()) if env else None, force_global_shell, cwd_str
            )

            try:
                # === NOTICE ===
                # We no longer set force_global_shell=True by default; let CMD.run handle .cmd/.bat quoting.
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
                logger.debug("Runner.run completed: returncode=%d", result.returncode)
                return result
            except subprocess.CalledProcessError as exc:
                logger.error("Runner.run failed: %s", exc)
                raise


    class Dependency:
        @staticmethod
        def in_venv() -> bool:
            logger.debug("Dependency.in_venv called")
            try:
                return ExternalDependency.in_venv()
            except Exception as exc:
                logger.error("Dependency.in_venv encountered error: %s", exc)
                raise

        @staticmethod
        def ensure(tool: str) -> None:
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
            if not isinstance(dep, str):
                raise TypeError(f"[PythonDependencies._dependency] 'dep' must be a string, got {type(dep).__name__}")
            if pack is not None and not isinstance(pack, str):
                raise TypeError(f"[PythonDependencies._dependency] 'pack' must be a string if provided, got {type(pack).__name__}")

            if importlib.util.find_spec(dep) is not None:
                logger.debug("PythonDependencies._dependency: module '%s' already installed", dep)
                return True

            pkg_name = pack or dep
            logger.info("PythonDependencies._dependency: installing package '%s' via CMD.pip_install", pkg_name)
            try:
                completed = CMD.pip_install(pkg_name)
                if completed.returncode == 0:
                    logger.debug("PythonDependencies._dependency: installation succeeded for '%s'", pkg_name)
                    return True
                else:
                    logger.error(
                        "PythonDependencies._dependency: pip_install returned non-zero code for '%s': %d",
                        pkg_name, completed.returncode,
                    )
                    return False
            except subprocess.CalledProcessError as exc:
                logger.error("PythonDependencies._dependency: pip_install failed for '%s': %s", pkg_name, exc)
                return False

        @staticmethod
        def try_import(package: str):
            if not isinstance(package, str):
                raise TypeError(f"[PythonDependencies.try_import] 'package' must be a string, got {type(package).__name__}")

            logger.debug("PythonDependencies.try_import: attempting import of '%s'", package)
            try:
                return importlib.import_module(package)
            except ImportError:
                logger.info(
                    "PythonDependencies.try_import: '%s' not found. Attempting installation via CMD.pip_install.",
                    package
                )
                success = MilesProcess.PythonDependencies._dependency(package)
                if not success:
                    raise RuntimeError(f"Failed to install package: {package}")

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


# Convenience aliases
run = MilesProcess.Runner.run
ensure_dependency = MilesProcess.Dependency.ensure
ensure_all_dependencies = MilesProcess.Dependency.ensure_all
in_virtualenv = MilesProcess.Dependency.in_venv
try_import = MilesProcess.PythonDependencies.try_import
