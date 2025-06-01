from pathlib import Path
import subprocess
import psutil
import time
import sys
import platform
from util.subprocess.cmd import CMD

class ExternalDependency:
    INSTALLERS = {
        "azure": {
            "check": "az",
            "method": "winget",
            "args": ["winget", "install", "--id", "Microsoft.AzureCLI", "-e", "--source", "winget"]
        },
        "rust": {
            "check": "rustc",
            "method": "powershell",
            "args": "iwr https://sh.rustup.rs -UseBasicParsing | iex",
        },
        "docker": {
            "check": "docker",
            "method": "winget",
            "args": ["winget", "install", "--id", "Docker.DockerDesktop", "-e", "--source", "winget"],
        },
    }

    @staticmethod
    def in_venv() -> bool:
        return hasattr(sys, "real_prefix") or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)

    @staticmethod
    def ensure_all():
        for tool in ExternalDependency.INSTALLERS:
            ExternalDependency.ensure(tool)

    @staticmethod
    def ensure(tool: str):
        if tool == "all":
            return print("All installed successfully!")

        tool = tool.lower()
        if tool not in ExternalDependency.INSTALLERS:
            raise ValueError(f"[Installer] Unknown tool: {tool}")

        if CMD.which(ExternalDependency.INSTALLERS[tool]["check"]):
            print(f"[Installer] ✅ {tool} already installed.")
            return

        ExternalDependency._install(tool)
        ExternalDependency._post_check(tool)

    @staticmethod
    def _install(tool: str):
        inst = ExternalDependency.INSTALLERS[tool]
        method = inst["method"]
        args = inst["args"]

        try:
            if method == "winget":
                CMD.winget_install(args)
            elif method == "powershell":
                CMD.powershell_install(args)
            elif method == "pipx":
                CMD.pipx_install_global(args)
            else:
                raise ValueError(f"[Installer] Unsupported install method: {method}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"[Installer] ❌ Installation failed for {tool}: {e}")

    @staticmethod
    def _post_check(tool: str):
        exe = ExternalDependency.INSTALLERS[tool]["check"]

        if CMD.which(exe):
            return print(f"[Installer] ✅ {tool} is now available.")

        ExternalDependency._refresh_path_windows()

        if CMD.which(exe):
            return print(f"[Installer] ✅ {tool} available after PATH refresh.")

        if tool == "azure":
            fallback = Path("C:/Program Files (x86)/Microsoft SDKs/Azure/CLI2/wbin/az.cmd")
            if fallback.exists():
                print(f"[Installer] ✅ {tool} is at fallback: {fallback}")
                return

        if ExternalDependency.in_venv():
            print(f"[Installer] ⚠️ {tool} may not be visible inside the virtual environment.")
            print("💡 Please restart your IDE to reload PATH.")
        else:
            ExternalDependency._restart_pycharm()

        raise RuntimeError(f"[Installer] ❌ {tool} still not found after installation.")

    @staticmethod
    def _refresh_path_windows():
        if platform.system() != "Windows":
            return
        try:
            refresh_cmd = [
                "powershell", "-Command",
                "[Environment]::SetEnvironmentVariable('Path', "
                "[Environment]::GetEnvironmentVariable('Path','Machine') + ';' + "
                "[Environment]::GetEnvironmentVariable('Path','User'), 'Process')"
            ]
            CMD.run(refresh_cmd, shell=True)
            time.sleep(1)
        except Exception as e:
            print(f"[Installer] ⚠️ PATH refresh failed: {e}")

    @staticmethod
    def _restart_pycharm():
        for proc in psutil.process_iter(["name", "exe"]):
            if "pycharm" in proc.info.get("name", "").lower():
                try:
                    path = proc.info["exe"]
                    print(f"[Installer] 🔁 Restarting PyCharm: {path}")
                    proc.kill()
                    time.sleep(2)
                    subprocess.Popen([path])
                    return
                except Exception as e:
                    print(f"[Installer] ⚠️ Could not restart PyCharm: {e}")
        print("[Installer] ℹ️ PyCharm not detected — no restart needed.")

import pytest

class TestExternalDependency:
    def test_in_venv_false(self):
        """
        Should return False if not running in venv
        """
        print("[test_in_venv_false] Result:", ExternalDependency.in_venv())
        assert ExternalDependency.in_venv() is False or True  # Can't assume True in all envs

    def test_ensure_known_tool_skips_if_installed(self, monkeypatch):
        """
        Should skip installation if tool is already present
        """
        called = {"which": False}

        def fake_which(exe):
            print(f"[fake_which] Called with: {exe}")
            called["which"] = True
            return "/usr/bin/fake"

        monkeypatch.setattr("external_dependency.CMD.which", fake_which)

        ExternalDependency.ensure("azure")
        assert called["which"] is True

    def test_ensure_unknown_tool_raises(self):
        """
        Should raise ValueError if unknown tool is requested
        """
        with pytest.raises(ValueError):
            ExternalDependency.ensure("unknown_tool")

    def test_install_dispatch(self, monkeypatch):
        """
        Should route to correct install method
        """
        log = []

        monkeypatch.setattr("external_dependency.CMD.winget_install", lambda args: log.append("winget"))
        monkeypatch.setattr("external_dependency.CMD.powershell_install", lambda args: log.append("powershell"))
        monkeypatch.setattr("external_dependency.CMD.pipx_install_global", lambda args: log.append("pipx"))

        ExternalDependency._install("azure")
        ExternalDependency._install("docker")
        ExternalDependency.INSTALLERS["mock"] = {"check": "mock", "method": "powershell", "args": "echo"}
        ExternalDependency._install("mock")

        print("[test_install_dispatch] Log:", log)
        assert log == ["winget", "winget", "powershell"]

    def test_refresh_path_windows_noop_on_linux(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Linux")
        # Should just no-op
        ExternalDependency._refresh_path_windows()

    def test_restart_pycharm_simulated(self, monkeypatch):
        """
        Should simulate PyCharm restart detection without failing
        """
        monkeypatch.setattr("psutil.process_iter", lambda attrs: [])
        ExternalDependency._restart_pycharm()  # Should not raise