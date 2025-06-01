import sys
import platform
import shlex
import subprocess
from shutil import which

class CMD:
    @staticmethod
    def run(
            cmd: str | list,
            *,
            shell=False,
            capture_output=True,
            check=True,
            text=True,
            env=None,
            force_global_shell=False
    ):
        """
        Runs a subprocess with optional global shell enforcement.

        Behavior:
        - If `cmd` is a string and shell=False, it's split safely.
        - On Windows, `.cmd` and `.bat` files are automatically wrapped with `cmd.exe /c`.
        - If `force_global_shell=True`, `cmd.exe /c` is prepended regardless.
        - Logs the final command to be run.
        """

        system_is_windows = platform.system() == "Windows"

        # Normalize string command input
        if isinstance(cmd, str) and not shell:
            cmd = shlex.split(cmd)

        # Auto-wrap .cmd/.bat on Windows if not already done
        if isinstance(cmd, list) and system_is_windows:
            first = cmd[0].lower()
            if first.endswith(".cmd") or first.endswith(".bat"):
                cmd = ["cmd.exe", "/c"] + cmd

        # Explicit force_global_shell wrapper
        if force_global_shell and system_is_windows:
            cmd = ["cmd.exe", "/c"] + cmd
            shell = False  # Ensure shell=False with manual cmd.exe call

        print(f"[CMD] Running: {cmd}")
        return subprocess.run(
            cmd,
            shell=shell,
            capture_output=capture_output,
            check=check,
            text=text,
            env=env,
        )

    @staticmethod
    def system_python() -> str:
        """Return a path to the system Python executable."""
        if platform.system() == "Windows":
            try:
                result = subprocess.run(["py", "-0p"], capture_output=True, text=True, check=True)
                return result.stdout.strip().splitlines()[0]
            except Exception as e:
                print(f"[CMD] Failed to resolve system Python via `py -0p`: {e}")
        return "python"  # fallback

    @staticmethod
    def pip_install(package: str | list, *, upgrade=False, global_scope=False):
        pkgs = [package] if isinstance(package, str) else package
        exe = CMD.system_python() if global_scope else sys.executable
        cmd = [exe, "-m", "pip", "install"]
        if upgrade:
            cmd.append("--upgrade")
        cmd.extend(pkgs)
        return CMD.run(cmd)

    @staticmethod
    def pipx_install_global(package: str):
        """Installs a package globally with pipx using system Python."""
        python = CMD.system_python()

        pipx_installed = subprocess.run(["pipx", "--version"], capture_output=True).returncode == 0
        if not pipx_installed:
            print("[Installer] pipx not found. Installing globally via system Python...")
            subprocess.run([python, "-m", "pip", "install", "--user", "pipx"], check=True)
            subprocess.run([python, "-m", "pipx", "ensurepath"], check=True)

        print(f"[Installer] Installing '{package}' globally with pipx...")
        return subprocess.run(["pipx", "install", package], check=True)

    @staticmethod
    def winget_install(command: list[str]):
        """
        Executes a winget command in a system shell with elevation.
        """
        if platform.system() != "Windows":
            raise RuntimeError("winget is only available on Windows.")

        full_cmd = " ".join(command)
        elevated = [
            "powershell", "-Command",
            f"Start-Process cmd -ArgumentList '/c {full_cmd}' -Verb runAs"
        ]
        print(f"[CMD] Elevating and running winget: {full_cmd}")
        subprocess.run(elevated, check=True)

    @staticmethod
    def powershell_install(script: str):
        return CMD.run(["powershell", "-Command", script], shell=True)

    @staticmethod
    def which(binary: str) -> str | None:
        return which(binary)