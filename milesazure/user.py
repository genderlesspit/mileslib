import itertools
import json
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


class ServicePrincipal:
    instance = None

    def __init__(self, token, version: str = "v1.0"):
        self.token = token
        self.version = version.strip("/")

    @classmethod
    def get_instance(cls):
        if cls.instance is None:
            cls.instance = cls()
        return cls.instance


class GraphAPI:
    instance = None

    def __init__(self, token, version: str = "v1.0"):
        self.token = token
        self.version = version.strip("/")

    @classmethod
    def get_instance(cls, token):
        if cls.instance is None:
            cls.instance = cls(token)
        return cls.instance

    @mileslib(retry=True)
    def request(self, method, resource, query_parameters, headers, json_body=None):
        url = f"https://graph.microsoft.com/{self.version}/{resource}"
        if query_parameters:
            url += f"?{query_parameters}"

        full_headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        if headers:
            full_headers.update(headers)

        log.info(f"[GraphAPI] Sending {method.upper()} request to: {url}")

        try:
            resp = requests.request(
                method=method.upper(),
                url=url,
                headers=full_headers,
                json=json_body
            )
            if not resp.ok:
                log.error(f"[GraphAPI] Error {resp.status_code}: {resp.text}")
                return None

            return resp.json()

        except Exception as e:
            log.exception(f"[GraphAPI] Request failed: {e}")
            return None


class AzureUserLogin:
    instance = None

    def __init__(self, project: str):
        self.project = project
        self.tenant_id = "27eb724b-5042-41e4-8c40-54b2662ffdfa"
        self._login()
        self.graph_client = GraphAPI.get_instance(self.graph_token)

    @classmethod
    def get_instance(cls, project):
        if cls.instance is None:
            cls.instance = cls(project)
        return cls.instance

    def _login(self):
        log.info(f"[AzureUserLogin] Logging into Azure for project '{self.project}'...")
        try:
            acct = azure_cli(["account", "show"], expect_json=True)
        except Exception as e:
            acct = None
        if not acct:
            azure_cli(["login", "--tenant", self.tenant_id, "--use-device-code"])

        self.user_info = azure_cli(["account", "show"], expect_json=True)
        log.info(f"[AzureUserLogin] Retrieved user info: {self.user_info}")

        token = azure_cli([
            "account", "get-access-token",
            "--scope", "https://graph.microsoft.com/.default"
        ])
        self.graph_token = token["accessToken"]
        log.info(f"[AzureUserLogin] Retrieved Graph token: {self.graph_token}")


class DockerImage:
    instances = {}

    def __init__(self, dockerfile: Path, image_name: str):
        if not dockerfile.exists():
            raise FileNotFoundError(f"Dockerfile not found at: {dockerfile}")
        if not isinstance(image_name, str):
            raise TypeError(f"Docker image name must be string!")

        self.dockerfile = dockerfile.resolve()
        self.image_name = image_name

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

    @classmethod
    def get_instance(cls, dockerfile: Path, image_name: str):
        if image_name in cls.instances:
            return cls.instances[image_name]
        instance = cls(dockerfile, image_name)
        cls.instances[image_name] = instance
        return instance

    def run(self, *args: str, interactive: bool = False, remove: bool = True) -> int:
        """
        Runs a container from the image with optional args.
        Args:
            *args: Commands to run inside the container (e.g. 'az', 'login')
            interactive: If True, attaches stdin/stdout (like a shell)
            remove: If True, auto-deletes container after run (--rm)
        Returns:
            Exit code of the process
        """
        cmd = ["docker", "run"]
        if interactive:
            cmd += ["-it"]
        if remove:
            cmd += ["--rm"]
        cmd += [self.image_name]
        if args:
            cmd += list(args)

        log.info(f"[DockerImage.run] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd)
        return result.returncode


class Docker:
    instance = None

    def __init__(self):
        self.uuid = uuid.uuid4()
        self.wsli = WSL.get_instance()
        self.base_cmd = ["-d", f"{self.wsli.distro}", "docker"]
        self.check_docker_ready()
        log.success(f"WSL Instance Initialized: {self.uuid}")

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
        try:
            self.wsli.run(['version', '--format', '{{.Server.Version}}'])
            return True
        except Exception:
            log.warning("Docker is not responding inside WSL ... Attempting to install ...")
            try:
                self.wsli.install_docker()
                self.run(['version', '--format', '{{.Server.Version}}'])
            except: raise RuntimeError

            return False

    @staticmethod
    def build(dockerfile: Path, image_name: str):
        if Docker.instance is None: Docker.get_instance()
        if not dockerfile.exists(): raise RuntimeError

        path = str(dockerfile.resolve())
        parent_path = str(dockerfile.parent.resolve())
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


class WSL:
    instance = None

    def __init__(self, distro: str = "Ubuntu-22.04"):
        self.path = r"C:\Windows\System32\wsl.exe"
        self.uuid = uuid.uuid4()
        self.base_cmd = [self.path]
        self.distro = distro
        self.check_distro(distro)
        self.run_cmd = self.base_cmd + ["-d", self.distro, "--exec", "bash", "-c"]
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

    def run(self, cmd: list | None = None) -> str:
        if not isinstance(cmd, list):
            raise TypeError("Expected a list of command arguments.")

        real_cmd = self.base_cmd + cmd
        log.info(f"[WSL.run_command] Running: {' '.join(real_cmd)}")

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

            if process.returncode != 0:
                raise RuntimeError(f"WSL command failed with return code {process.returncode}")

            decoded_output = self._decode_wsl_output(output_bytes)

            for line in decoded_output.splitlines():
                print(f"[WSL] {line.strip()}", flush=True)

            return decoded_output

        except Exception as e:
            log.exception("[WSL.run_command] Failed to execute command.")
            raise

    install_cmds = [
        # 1. Update package lists
        ["sudo", "apt-get", "update"],

        # 2. Install prerequisite packages
        ["sudo", "apt-get", "install", "-y", "ca-certificates", "curl", "gnupg", "lsb-release"],

        # 3. Create keyring directory
        ["sudo", "mkdir", "-p", "/etc/apt/keyrings"],

        # 4. Download Docker GPG key
        ["bash", "-c", (
            "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | "
            "sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
        )],

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

    def install_docker(self):
        for cmd in self.install_cmds:
            try: self.run(cmd)
            except Exception as e: raise RuntimeError(e)

def azure_cli(
        docker_img: DockerImage,
        cmd: list[str],
        expect_json: bool = True,
        interactive: bool = False
) -> dict | str | None:
    """
    Runs Azure CLI commands inside the provided Docker image.

    Args:
        docker_img: DockerImage instance
        cmd: List of Azure CLI command parts (e.g., ["account", "show"])
        expect_json: Parse stdout as JSON if True
        interactive: Attach stdin for login or other interactive use

    Returns:
        Parsed JSON dict, raw string, or None
    """
    base_cmd = ["az"] + cmd
    if expect_json:
        base_cmd += ["--output", "json"]

    log.info(f"[dockerized_azure_cli] Running inside container: {' '.join(base_cmd)}")
    result = subprocess.run(
        ["docker", "run", "--rm", "-i", docker_img.image_name] + base_cmd,
        capture_output=not interactive,
        text=True
    )

    if interactive:
        return None  # output goes to terminal directly

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if stderr:
        log.error(f"[dockerized_azure_cli] STDERR: {stderr}")
        return None

    if not stdout:
        log.warning(f"[dockerized_azure_cli] Empty STDOUT for command: {' '.join(cmd)}")
        return None

    if expect_json:
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            log.debug(f"[dockerized_azure_cli] Non-JSON output: {stdout}")

    return stdout


if __name__ == "__main__":
    path = Path("C:\\Users\\cblac\\PycharmProjects\\mileslib2\\foobar\\Dockerfile.foobar")
    log.info("foobar")
    Docker.get_instance()
    # DockerImage.get_instance(path, "foobar")
    # user = AzureUserLogin("foobar")
