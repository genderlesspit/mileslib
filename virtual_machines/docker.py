import itertools
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
import requests
import select
from fastapi import requests
from loguru import logger as log
from context.decorator import mileslib
from util.sanitization import Sanitization


class DockerImage:
    instances = {}

    def __init__(self, dockerfile: Path):
        if not dockerfile.exists():
            raise FileNotFoundError(f"Dockerfile not found at: {dockerfile}")

        self.dockerfile_path = dockerfile
        self.dockerfile_str = str(dockerfile.resolve())
        self.dockerfile_parent_path = str(self.dockerfile_path.parent.resolve())
        self.image_name = Sanitization.standard(self.dockerfile_str.replace("Docker.", ""))
        #self.base_cmd = #####

        if not self.find_image():
            Docker.build(self.dockerfile, self.image_name)

    def find_image(self) -> bool:
        cmd = ["docker", "images", "--format", "{{.Repository}}", self.image_name]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout.strip()
            if result.returncode != 0 or not output:
                log.warning(f"[DockerImage.find_image] Image '{self.image_name}' not found.")
                return False
            log.info(f"[DockerImage.find_image] Found image '{self.image_name}'.")
            return True
        except Exception as e:
            log.error(f"[DockerImage.find_image] Error checking image: {e}")
            return False

    def build(self):
        if self.instance is None: self.get_instance()
        if not self.dockerfile.exists(): raise RuntimeError

        path = str(dockerfile.resolve())
        cmd = ["docker", "build", "-f", path, "-t", image_name, parent_path]

        log.info(f"[Docker.build] Running command: {' '.join(cmd)}")
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True
            )

            if process.stdout is None:
                raise RuntimeError("Docker build stdout is None!")

            for line in iter(process.stdout.readline, ''):
                print(f"[Docker] {line.strip()}", flush=True)

            process.stdout.close()
            process.wait()

            if process.returncode != 0:
                raise RuntimeError(f"Docker build failed for image: {image_name}")

        except Exception as e:
            log.exception(f"[Docker.build] Exception: {e}")
            raise


    @classmethod
    def get_instance(cls, dockerfile: Path, image_name: str):
        if image_name in cls.instances:
            return cls.instances[image_name]
        instance = cls(dockerfile, image_name)
        cls.instances[image_name] = instance
        return instance

    def run(self, cmd: list):
        """
        Runs a container from the image with optional args.
        Args:
            *args: Commands to run inside the container (e.g. 'az', 'login')
            interactive: If True, attaches stdin/stdout (like a shell)
            remove: If True, auto-deletes container after run (--rm)
        Returns:
            Exit code of the process
        """
        cmd = self.base_cmd + cmd
        result = Docker.run(cmd)

class Docker:
    instance = None

    def __init__(self):
        self.uuid = uuid.uuid4()
        self.wsli = WSL.get_instance()
        self.base_cmd = ["-d", f"{self.wsli.distro}", "docker"]
        self.check_docker_ready()
        log.success(f"Docker Instance Initialized: {self.uuid}")

    @classmethod
    def get_instance(cls):
        if cls.instance is None:
            cls.instance = cls()
        return cls.instance

    def run(self, cmd: list):
        if not isinstance(cmd, list): raise TypeError
        real_cmd = self.base_cmd + cmd
        self.wsli.run(real_cmd)
        return self.wsli.run(real_cmd)

    def check_docker_ready(self):
        cmd = self.base_cmd + ['version', '--format', '{{.Server.Version}}']

        try:
            self.wsli.run(cmd)
            return True
        except Exception:
            log.warning("Docker is not responding inside WSL ... Attempting to install ...")
            try:
                self.wsli.looper(self.wsli.INSTALL_CMDS)
                self.wsli.run(cmd)
            except Exception: raise RuntimeError("Docker couldn't respond even after installation!")

            return False

class WSL:
    instance = None

    def __init__(self, distro: str = "Ubuntu-22.04"):
        self.path = r"C:\Windows\System32\wsl.exe"
        self.uuid = uuid.uuid4()
        self.base_cmd = [self.path]
        self.distro = distro
        self.check_distro(distro)
        self.run_cmd = self.base_cmd + ["-d", self.distro, "--exec", "bash", "-c"]
        self.passwordless_sudo()
        log.success(f"WSL Instance Initialized: {self.uuid}, {self.distro}")

    @classmethod
    def get_instance(cls):
        if shutil.which("wsl") is None:
            log.warning("WSL is not installed or not in PATH! Attempting install...")
            cls.install_wsl()
            if shutil.which("wsl") is None:
                raise RuntimeError("WSL installation failed or not available on PATH.")
        else:
            log.success("WSL is installed and available")

        if cls.instance is None:
            cls.instance = cls()
        return cls.instance

    @staticmethod
    def install_wsl():
        try:
            result = subprocess.run(["wsl", "--install"], check=True)
            log.success("WSL install initiated.")
        except Exception as e:
            log.error("WSL installation failed.")
            raise RuntimeError("WSL installation failed.") from e

    def check_distro(self, distro: str) -> str:
        list_cmd = ["--list", "--quiet"]
        install_cmd =["cmd.exe", "/c", "start", "cmd.exe", "/k", f"wsl --install -d {distro}"]

        def check():
            try:
                listed_distros = self.run(list_cmd)
                if distro in listed_distros:
                    log.info(f"✅ Distro '{distro}' found.")
                else:
                    raise RuntimeError(f"❌ Distro '{distro}' not found.")
            except subprocess.CalledProcessError as e:
                log.error("WSL list command failed.")
                raise RuntimeError("WSL list command failed.") from e

        def _wait_for_enter(flag):
            input()  # Blocks until Enter is pressed
            flag["break"] = True

        def install():
            subprocess.Popen(install_cmd, shell=True)
            log.info("⏳ Waiting for user to finish install... (press Enter to skip wait)")

            flag = {"break": False}
            threading.Thread(target=_wait_for_enter, args=(flag,), daemon=True).start()

            spinner = itertools.cycle(["|", "/", "-", "\\"])

            while True:
                sys.stdout.write(f"\rInstalling... {next(spinner)} Still waiting for '{self.distro}'... ")
                sys.stdout.flush()
                time.sleep(1)

                if flag["break"]:
                    log.warning("⛔ Manual break triggered by Enter.")
                    break

                try:
                    result = subprocess.run(
                        list_cmd,
                        capture_output=True, text=True, check=True, timeout=5
                    )
                    if self.distro.lower() in result.stdout.lower():
                        print(f"\n✅ Distro '{self.distro}' is now installed.")
                        break
                except Exception:
                    pass

        if not isinstance(distro, str):
            raise TypeError("distro must be a string")

        try:
            result = check()
            log.info("WSL distros available:\n", result)
            return distro
        except RuntimeError:
            time.sleep(1)
            log.info("Continuing with Distro Installation...")
            install()
            return distro
        except subprocess.CalledProcessError as e:
            log.error("❌ Failed to check installed distros.")
            log.error("stdout: {}", e.stdout)
            log.error("stderr: {}", e.stderr)
            raise RuntimeError("WSL --list failed. WSL may not be fully set up.") from e

    def delete_distro(self):
        """
        Unregisters (deletes) the WSL distro specified in self.distro.
        """
        try:
            self.run(
                ["--unregister", self.distro],
            )
            log.success(f"✅ Distro '{self.distro}' has been deleted.")
        except subprocess.CalledProcessError as e:
            log.error(f"❌ Failed to delete distro '{self.distro}': {e.stderr.strip()}")
            raise RuntimeError(f"Could not unregister distro '{self.distro}'") from e

    @staticmethod
    def _decode_wsl_output(output_bytes: bytes) -> str:
        """
        Attempt to decode WSL command output.
        - Tries UTF-8 first, falls back to UTF-16 (ignoring decode errors).
        - Strips nulls, condenses double spaces, removes blank lines.
        - Returns a single cleaned string (newline-separated).
        """
        try:
            output = output_bytes.decode("utf-8")
        except UnicodeDecodeError:
            output = output_bytes.decode("utf-16", errors="ignore")

        normalized = output.replace('\x00', '').replace('  ', ' ')
        cleaned_lines = [line.strip() for line in normalized.splitlines() if line.strip()]
        return "\n".join(cleaned_lines)

    IGNORE_CODES = [9]

    def run(self, cmd: list | None = None, ignore_codes: list[str] | None = None) -> str:
        if not isinstance(cmd, list):
            raise TypeError("Expected a list of command arguments.")

        if ignore_codes is None:
            ignore_codes = []
        ignore_codes = self.IGNORE_CODES + ignore_codes

        real_cmd = self.base_cmd + cmd
        log.info(f"[WSL.run_command] Running: {' '.join(real_cmd)}")

        # Spinner setup
        spinner_running = True

        def _spinner():
            for c in itertools.cycle(r"\|/-"):
                if not spinner_running:
                    break
                print(f"\r[WSL] Running... {c}", end="", flush=True)
                time.sleep(0.1)
            print("\r", end="", flush=True)  # Clean up line

        spinner_thread = threading.Thread(target=_spinner)
        spinner_thread.start()

        try:
            process = subprocess.Popen(
                real_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            if process.stdout is None:
                raise RuntimeError("WSL command stdout is None!")

            output_bytes = process.stdout.read()
            process.stdout.close()
            process.wait()

            if process.returncode != 0 and (ignore_codes is None or process.returncode not in ignore_codes):
                raise RuntimeError(f"WSL command failed with return code {process.returncode}")

            decoded_output = self._decode_wsl_output(output_bytes)

            for line in decoded_output.splitlines():
                print(f"[WSL] {line.strip()}", flush=True)

            return decoded_output

        except Exception as e:
            log.exception("[WSL.run_command] Failed to execute command.")
            raise

        finally:
            spinner_running = False
            spinner_thread.join()

    INSTALL_CMDS = [
        # 1. Update package lists
        ["sudo", "apt-get", "update"],

        # 2. Install prerequisite packages
        ["sudo", "apt-get", "install", "-y", "ca-certificates", "curl", "gnupg", "lsb-release"],

        # 3. Create keyring directory
        ["sudo", "mkdir", "-p", "/etc/apt/keyrings"],

        # 4. Download Docker GPG key
        ["bash", "-c",
         "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo tee /etc/apt/keyrings/docker.gpg > /dev/null"],

            # 5. Add Docker repository
        ["bash", "-c", (
            'echo "deb [arch=$(dpkg --print-architecture) '
            'signed-by=/etc/apt/keyrings/docker.gpg] '
            'https://download.docker.com/linux/ubuntu '
            '$(lsb_release -cs) stable" | '
            'sudo tee /etc/apt/sources.list.d/docker.list > /dev/null'
        )],

        # 6. Update package lists again
        ["sudo", "apt-get", "update"],

        # 7. Install Docker components
        ["sudo", "apt-get", "install", "-y",
         "docker-ce", "docker-ce-cli", "containerd.io",
         "docker-buildx-plugin", "docker-compose-plugin"],

        # 8. Start Docker daemon in background
        ["bash", "-c", "sudo nohup dockerd > /dev/null 2>&1 &"],

        # 9. Add docker group (harmless if exists)
        ["sudo", "groupadd", "docker"],

        # 10. Add user to docker group
        ["sudo", "usermod", "-aG", "docker", "$USER"],
    ]

    def looper(self, cmd_list: list, ignore_codes: list = None):
        for cmd in cmd_list:
            try: self.run(cmd, ignore_codes)
            except Exception as e: raise RuntimeError(e)

    PASSWORDLESS_SUDO_CMDS = [
        # Get the username dynamically
        ["bash", "-c", "USER=$(whoami) && echo \"$USER ALL=(ALL) NOPASSWD:ALL\" | sudo tee /etc/sudoers.d/$USER"],
        # Make the sudoers file secure
        ["bash", "-c", "sudo chmod 440 /etc/sudoers.d/$(whoami)"],
    ]

    def passwordless_sudo(self):
        key = f"{self.passwordless_sudo.__name__}"
        val = os.getenv(key)
        if val is None:
            self.looper(self.PASSWORDLESS_SUDO_CMDS)
            os.environ.setdefault(key, "True")
        return
