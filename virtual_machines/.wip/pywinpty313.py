import json
import os
import subprocess
import time
import uuid
from pathlib import Path
import socket

import requests
from loguru import logger as log

class PyWinPTY313:
    #this is the client to call pywinpty311
    instance = None

    def __init__(self):
        self.uuid = uuid.uuid4()
        self.py311 = Py311.get_instance()
        self.venv = self.py311.venv_instance
        log.debug(subprocess.run([f"{self.venv}", "pywinpty311.py"]))
        #_ = self.call
        #_ = self.check_socket
        log.success(f"pywinpty successfully initialized: {self.uuid}")

    @classmethod
    def get_instance(cls):
        if cls.instance:
            return cls.instance
        cls.instance = cls()
        return cls.instance


class Py311:
    instance = None
    venv_instance = None

    def __init__(self):
        self.uuid = uuid.uuid4()
        _ = self.has_python_311
        self.venv_str = str(self.venv)
        _ = self.imports
        log.success(f"Py311 successfully initialized: {self.uuid}")

    @classmethod
    def get_instance(cls):
        if cls.instance:
            return cls.instance
        cls.instance = cls()
        return cls.instance

    @property
    def has_python_311(self) -> bool:
        def install_python_311():
            import urllib.request
            import tempfile

            log.info("[Py311] Python 3.11 not found. Attempting installation...")

            installer_url = "https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe"
            installer_path = Path(tempfile.gettempdir()) / "python311_installer.exe"

            # Download installer
            log.info(f"[Py311] Downloading installer to {installer_path}...")
            log.warning(f"[Py311] Please do not exit!")
            urllib.request.urlretrieve(installer_url, installer_path)

            # Run installer silently
            log.debug("[Py311] Running silent installer...")
            subprocess.run([
                str(installer_path),
                "/quiet",
                "InstallAllUsers=0",
                "PrependPath=1",
                "Include_test=0"
            ], check=True)

            log.info("[Py311] Installation complete.")

        def check_for_python_311():
            try:
                result = subprocess.run(
                    ["py", "-3.11", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if result.stderr: return False
                return result.returncode == 0 and result.stdout.startswith("Python 3.11")
            except Exception:
                raise RuntimeError

        while check_for_python_311() is False:
            try: install_python_311()
            except Exception: raise RuntimeError
        log.debug("[Py311] Python version 3.11 found!")
        return True

    @property
    def venv(self):
        venv_path = Path.cwd() / "venv_311"
        python_path = venv_path / "Scripts" / "python.exe"

        if self.venv_instance: return self.venv_instance

        while not python_path.exists():
            log.info("[Py311] venv_311 not found. Creating...")
            try:
                subprocess.run(["py", "-3.11", "-m", "venv", str(venv_path)], check=True)
            except subprocess.CalledProcessError as e:
                log.error(f"[Py311] Failed to create venv_311")
                raise RuntimeError(e)
        log.debug(f"[Py311] venv_311 called at {python_path}")
        self.venv_instance = python_path
        return self.venv_instance

    @property
    def imports(self):
        py311 = self.venv_str

        def check_pywinpty():
            result = subprocess.run([py311, "-c", "import winpty"], capture_output=True, text=True)
            log.debug(result)
            return result.returncode == 0  # success

        def check_fastapi():
            result = subprocess.run([py311, "-c", "import fastapi"], capture_output=True, text=True)
            log.debug(result)
            return result.returncode == 0  # success

        def check_uvicorn():
            result = subprocess.run([py311, "-c", "import uvicorn"], capture_output=True, text=True)
            log.debug(result)
            return result.returncode == 0  # success

        while not check_pywinpty() or not check_fastapi() or not check_uvicorn():
            log.info("[Py311] pywinpty not found. Installing...")
            try:
                subprocess.run([py311, "-m", "pip", "install", "pywinpty"], check=True)
                subprocess.run([py311, "-m", "pip", "install", "fastapi"], check=True)
                subprocess.run([py311, "-m", "pip", "install", "uvicorn"], check=True)
            except Exception as e: raise RuntimeError(e)
        return True

if __name__ == "__main__":
    PyWinPTY313.get_instance()