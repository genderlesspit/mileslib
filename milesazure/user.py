import asyncio
import json
import logging
import subprocess
import time
import requests
from pathlib import Path
import shutil

from fastapi import requests

from context.decorator import mileslib
from milesazure.tenant import tenant_id

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)



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
    def request(self, method, resource, query_parameters, headers, json_body = None):
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
        try: acct = azure_cli(["account", "show"], expect_json=True)
        except Exception as e: acct = None
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

    @classmethod
    def get_instance(cls):
        if shutil.which("docker") is None:
            log.warning("❌ Docker is not installed or not in PATH! Attempting install...")
            cls.install_docker()
            if shutil.which("docker") is None:
                raise RuntimeError("Docker installation failed or not available on PATH.")
        else:
            log.info("✅ Docker is installed and available")

        Docker.check_daemon()

        if cls.instance is None:
            cls.instance = cls()
        return cls.instance

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


    @staticmethod
    def install_docker():
        if shutil.which("winget"):
            log.info("winget is available.")
        else:
            log.error("winget is NOT on PATH!")

        result = subprocess.run(
            ["winget", "install", "--id", "Docker.DockerDesktop", "-e"],
            check=False
        )
        print(f"Exit code: {result.returncode}")

    @staticmethod
    def check_daemon():
        try:
            subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            raise RuntimeError("❌ Docker daemon not running. Please start Docker Desktop.")

class WSL:
    instance = None

    @classmethod
    def get_instance(cls):
        if shutil.which("wsl") is None:
            log.warning("❌ WSL is not installed or not in PATH! Attempting install...")
            cls.install_wsl()
            if shutil.which("wsl") is None:
                raise RuntimeError("WSL installation failed or not available on PATH.")
        else:
            log.info("✅ WSL is installed and available")

        if cls.instance is None:
            cls.instance = cls()
        return cls.instance

    @staticmethod
    def install_wsl():
        try:
            result = subprocess.run(["wsl", "--install"], check=True)
            log.info("✅ WSL install initiated.")
        except Exception as e:
            log.exception("❌ WSL installation failed.")
            raise RuntimeError("WSL installation failed.") from e

    @staticmethod
    def check_distro_ready():
        # Minimal check to see if WSL2 is running
        try:
            subprocess.run(["wsl", "-e", "ls"], check=True, stdout=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    @staticmethod
    def run_command(cmd: str, distro: str | None = None):
        if WSL.instance is None:
            WSL.get_instance()

        base_cmd = ["wsl"]
        if distro:
            base_cmd += ["-d", distro]
        base_cmd += ["--exec", "bash", "-c", cmd]

        log.info(f"[WSL.run_command] Running: {' '.join(base_cmd)}")
        try:
            process = subprocess.Popen(
                base_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True
            )

            if process.stdout is None:
                raise RuntimeError("WSL command stdout is None!")

            for line in iter(process.stdout.readline, ''):
                print(f"[WSL] {line.strip()}", flush=True)

            process.stdout.close()
            process.wait()

            if process.returncode != 0:
                raise RuntimeError(f"WSL command failed with return code {process.returncode}")

        except Exception as e:
            log.exception("[WSL.run_command] Failed to execute command.")
            raise


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
    DockerImage.get_instance(path, "foobar")
    #user = AzureUserLogin("foobar")
