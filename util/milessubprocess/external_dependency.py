from pathlib import Path
import subprocess
import psutil
import time
import sys
import platform
from util.milessubprocess.cmd import CMD

class ExternalDependency:
    INSTALLERS = {
        "milesazure": {
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
        import itertools
        import threading

        exe = ExternalDependency.INSTALLERS[tool]["check"]

        # ✅ Immediate success
        if CMD.which(exe):
            print(f"[Installer] ✅ {tool} is now available.")
            return

        ExternalDependency._refresh_path_windows()

        # 🌀 Spinner + manual override setup
        spinner = itertools.cycle("|/-\\")
        max_wait = 9000  # seconds
        interval = 0.5   # seconds
        waited = 0
        user_interrupted = False

        def wait_for_enter():
            nonlocal user_interrupted
            input("[Installer] ⏸️  Press ENTER to skip waiting and continue manually...")
            user_interrupted = True

        enter_thread = threading.Thread(target=wait_for_enter, daemon=True)
        enter_thread.start()

        print(f"[Installer] ⏳ Waiting for {tool} to appear on PATH...")

        while waited < max_wait:
            sys.stdout.write(f"\r[Installer] {next(spinner)} Checking for {exe} ({waited:.1f}s)...")
            sys.stdout.flush()
            time.sleep(interval)
            waited += interval

            if CMD.which(exe):
                print(f"\r[Installer] ✅ {tool} is now available after {waited:.1f}s.")
                return

            if user_interrupted:
                print(f"[Installer] ⏭️  Skipping wait. Proceeding manually...")
                break

        # ✅ Fallback path for Azure CLI
        if tool == "milesazure":
            fallback = Path("C:/Program Files (x86)/Microsoft SDKs/Azure/CLI2/wbin/az.cmd")
            if fallback.exists():
                print(f"\r[Installer] ✅ {tool} available at fallback: {fallback}")
                ExternalDependency.INSTALLERS[tool]["check"] = str(fallback)
                return

        print("[Installer] ⚠️ Tool still not detected after wait.")

        if ExternalDependency.in_venv():
            print(f"[Installer] ⚠️ {tool} may not be visible inside the virtual environment.")
        else:
            response = input("[Installer] 🔁 Restart IDE now? (y/N): ").strip().lower()
            if response == "y":
                ExternalDependency._restart_pycharm()
            else:
                print("[Installer] ❌ IDE not restarted — you may need to do it manually.")

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