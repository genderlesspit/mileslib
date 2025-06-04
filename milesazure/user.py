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

def azure_cli(cmd: list[str], expect_json: bool = True) -> dict | str | None:
    azure_path = "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.CMD"
    full_cmd = [azure_path] + cmd
    if expect_json is True: full_cmd = [azure_path] + cmd + ["--output", "json"]

    log.info(f"Running Azure CLI with: {' '.join(full_cmd)}")

    try:
        # Let interactive commands stream output
        if "login" in cmd:
            subprocess.run(full_cmd, check=True)
            return None

        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if stderr:
            log.error(f"[azure_cli] STDERR: {stderr}")
            return None

        if not stdout:
            log.warning(f"[azure_cli] Empty STDOUT for command: {' '.join(cmd)}")
            return None

        if expect_json:
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                log.debug(f"[azure_cli] Non-JSON output: {stdout}")
        return stdout

    except Exception as e:
        log.exception(f"[azure_cli] Exception occurred: {e}")
        raise RuntimeError(f"Failed to execute command: {cmd}") from e

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

class Docker:
    instance = None

    @classmethod
    def get_instance(cls):
        if shutil.which("docker") is None:
            log.warning("❌ Docker is not installed or not in PATH! Installing...")
            Docker.install_docker()
        else:
            log.info("✅ Docker is installed")
            cls.instance = cls()
        return cls.instance

    @staticmethod
    def build(dockerfile: Path, image_name: str):
        if not dockerfile.exists(): raise RuntimeError
        path = [str(dockerfile.resolve())]
        cmd = ["docker", "build", "-f"] + path + ["-t", f"{image_name}"]
        subprocess.run(cmd)

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

if __name__ == "__main__":
    Docker.install_docker()
    log.info("DEBUG MODE")
    user = AzureUserLogin("foobar")
