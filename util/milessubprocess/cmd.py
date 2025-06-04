# cmd.py

import logging
import platform
import shlex
import subprocess
import sys
from pathlib import Path
from shutil import which as std_which
from typing import Union, List, Optional, Dict

logger = logging.getLogger(__name__)


class CMD:
    @staticmethod
    def run(
            cmd: Union[str, List[str]],
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
        Runs a subprocess command. On Windows, if you pass a list where the first
        element is the full path to a .cmd or .bat, subprocess.run([...], shell=False)
        will automatically handle the spaces in e.g. "C:\\Program Files\\…\\az.cmd".

        - If `cmd` is a string and shell=False, splits with shlex.
        - We no longer nest "cmd.exe /c". Instead, let subprocess.run use the direct path.
        - `force_global_shell` is effectively ignored when `cmd` is already a list
          pointing to a .cmd/.bat file with spaces. subprocess.run will handle it.
        """
        # --- Type checks ---
        if not isinstance(cmd, (str, list)):
            raise TypeError(f"[CMD.run] 'cmd' must be a str or list, got {type(cmd).__name__}")
        if env is not None and not isinstance(env, dict):
            raise TypeError(f"[CMD.run] 'env' must be a dict or None, got {type(env).__name__}")
        if cwd is not None and not isinstance(cwd, (str, Path)):
            raise TypeError(f"[CMD.run] 'cwd' must be str, pathlib.Path, or None, got {type(cwd).__name__}")

        # Determine if running on Windows
        system_is_windows = (platform.system() == "Windows")

        # Convert cwd from Path to str if necessary
        cwd_str: Optional[str]
        if isinstance(cwd, Path):
            cwd_str = str(cwd)
        else:
            cwd_str = cwd

        # If cmd is a string and not using a shell, split it
        if isinstance(cmd, str) and not shell:
            cmd = shlex.split(cmd)

        # On Windows, if cmd is a list and first entry ends with .cmd/.bat, leave it alone
        if isinstance(cmd, list) and system_is_windows:
            first = cmd[0].strip('"')
            if first.lower().endswith((".cmd", ".bat")):
                pass

        # If force_global_shell requested on Windows, wrap in ["cmd.exe", "/c"] if not already wrapped
        if force_global_shell and system_is_windows:
            if isinstance(cmd, list) and cmd[:2] != ["cmd.exe", "/c"]:
                cmd = ["cmd.exe", "/c"] + cmd
                shell = False

        # Logging the raw command invocation
        logger.info("Running command: %r (cwd=%r)", cmd, cwd_str)

        # Execute the subprocess
        try:
            result = subprocess.run(
                cmd,
                shell=shell,
                capture_output=capture_output,
                check=check,
                text=text,
                env=env,
                cwd=cwd_str,
            )
        except subprocess.CalledProcessError as exc:
            # Log failure with stderr if available
            stderr_text = exc.stderr if exc.stderr else ""
            logger.error(
                "Command failed (returncode=%d). cmd=%r%s",
                exc.returncode,
                cmd,
                f", stderr={stderr_text!r}" if stderr_text else ""
            )
            raise

        # Log success if returncode == 0, warning otherwise (only if check=False)
        if result.returncode == 0:
            logger.info("Command succeeded (returncode=0)")
        else:
            logger.warning("Command completed with non-zero exit (returncode=%d)", result.returncode)

        return result

    @staticmethod
    def which(binary: str) -> Optional[str]:
        """
        Return the full unquoted path to a binary if found in PATH,
        or check common Azure CLI fallbacks on Windows.

        We do NOT quote the returned path—subprocess.run([...], shell=False)
        will handle spaces automatically.
        """
        path = std_which(binary)
        if path:
            return path

        if binary.lower() == "az":
            fallback_paths = [
                r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
                r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
            ]
            for fb in fallback_paths:
                fb_path = Path(fb)
                if fb_path.exists():
                    print(f"[CMD.which] ✅ Fallback found for {binary}: {fb_path}")
                    return str(fb_path)

        return None

    @staticmethod
    def system_python() -> str:
        """Return a path to the system Python executable, preferring 'py -0p' on Windows."""
        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ["py", "-0p"], capture_output=True, text=True, check=True
                )
                return result.stdout.strip().splitlines()[0]
            except Exception as e:
                print(f"[CMD] Warning: Failed to resolve system Python via 'py -0p': {e!r}")
        return "python"

    @staticmethod
    def pip_install(
            package: Union[str, List[str]],
            *,
            upgrade: bool = False,
            global_scope: bool = False,
    ) -> subprocess.CompletedProcess:
        """
        Installs one or more packages via pip.
        If global_scope is True, uses the system Python; otherwise uses current interpreter.
        """
        pkgs = [package] if isinstance(package, str) else package
        exe = CMD.system_python() if global_scope else sys.executable
        cmd = [exe, "-m", "pip", "install"]
        if upgrade:
            cmd.append("--upgrade")
        cmd.extend(pkgs)
        print(f"[CMD] pip_install -> {cmd!r}")
        return CMD.run(cmd)

    @staticmethod
    def pipx_install_global(package: str) -> subprocess.CompletedProcess:
        """
        Installs a package via pipx using system Python.
        """
        python = CMD.system_python()
        pipx_installed = (
                subprocess.run(["pipx", "--version"], capture_output=True).returncode == 0
        )
        if not pipx_installed:
            print("[CMD] pipx not found; installing pipx via system Python...")
            subprocess.run([python, "-m", "pip", "install", "--user", "pipx"], check=True)
            subprocess.run([python, "-m", "pipx", "ensurepath"], check=True)

        print(f"[CMD] pipx_install_global -> ['pipx', 'install', {package!r}]")
        return subprocess.run(["pipx", "install", package], check=True)

    @staticmethod
    def winget_install(command: List[str]) -> None:
        """
        Executes a winget command in an elevated PowerShell on Windows.
        """
        if platform.system() != "Windows":
            raise RuntimeError("winget is only available on Windows.")

        full_cmd = " ".join(command)
        elevated = [
            "powershell",
            "-Command",
            f"Start-Process cmd -ArgumentList '/c {full_cmd}' -Verb runAs",
        ]
        print(f"[CMD] Elevating and running winget: {full_cmd!r}")
        subprocess.run(elevated, check=True)

    @staticmethod
    def powershell_install(script: str) -> subprocess.CompletedProcess:
        """
        Runs a PowerShell script (with -Command).
        """
        print(f"[CMD] powershell_install -> script={script!r}")
        return CMD.run(["powershell", "-Command", script], shell=True)
