import json
import subprocess
import sys
import uuid
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from loguru import logger as log
from virtual_machines.docker import DockerImage
# import pywinpty
from mileslib_infra import Global

@dataclass
class SPCredentials:
    tenant_id: str
    client_id: str
    client_secret: str

class AzureCLI:
    instances = {}

    def __init__(self, mileslib: Global, user: bool, user_str: str, credentials: SPCredentials = None):
        self.mileslib = mileslib
        self.uuid = uuid.uuid4()
        self.user = user
        self.user_str = user_str
        self.credentials = credentials
        _ = self.path
        self.docker_image = DockerImage.get_instance(self.path, rebuild=True)
        self.path_wsl = self.docker_image.to_wsl_path(self.path)
        self.mileslib_dir_wsl = self.docker_image.to_wsl_path(self.mileslib.directory)
        self.image_name = self.docker_image.image_name
        _ = self.dir
        self.dir_wsl = self.docker_image.to_wsl_path(self.dir)
        self.metadata = self.init()

    @classmethod
    def get_instance(cls, mileslib, user: bool, credentials: SPCredentials = None):
        if user is True:
            image_name = "user"
            credentials = None
        else:
            image_name = "sp"
            if not credentials: raise RuntimeError("You must provide credentials to login as SP!")

        for key in cls.instances:
            if image_name == key: return cls.instances[key]

        instance = cls(mileslib, user, image_name, credentials)
        cls.instances[image_name] = instance
        return instance

    @cached_property
    def path(self):
        path = self.mileslib.directory / f"Dockerfile.{self.user_str}"
        return path

    @cached_property
    def dir(self):
        dir = self.mileslib.directory / f"azure_{self.image_name}"
        dir.mkdir(exist_ok=True)
        Path(dir / "commands").mkdir(parents=True, exist_ok=True)
        return dir

    @cached_property
    def azure_profile(self):
        azure_profile_path = self.mileslib.directory / "azure_user" / "azureProfile.json"
        if not azure_profile_path.exists(): AzureCLI.get_instance(self.mileslib, user=True)
        with open(azure_profile_path, "r", encoding="utf-8-sig") as file:
            data = json.load(file)
            return data

    @cached_property
    def base_cmd(self):
        common = [
            "run", "--rm",
            "-v", f"{self.mileslib_dir_wsl}:/app",
            "-v", f"{self.dir_wsl}:/root/.azure",
            "-e", "AZURE_CONFIG_DIR=/root/.azure",
            "-w", "/app",
        ]

        if self.user is True:
            return common + [self.image_name]

        creds = self.credentials
        if not self.credentials: raise ValueError

        return common + [
            "-e", f"AZURE_CLIENT_ID={creds.client_id}",
            "-e", f"AZURE_CLIENT_SECRET={creds.client_secret}",
            "-e", f"AZURE_TENANT_ID={creds.tenant_id}",
            self.image_name
        ]

    def init(self):
        log.debug(self.docker_image.docker.wsli.run(["ping", "-c", "1", "microsoft.com"]))
        try: cached_user = self.run(["az account show"], headless=True, expect_json=True)
        except Exception:
            self.run([], headless=False)
            log.error("Please create a valid user login session with Azure CLI... Ending this session...")
            sys.exit()
        log.success(f"Azure CLI session successfully initialized: {self.uuid}, {self.image_name}")
        return cached_user

    def run(self, cmd: list | str = None, headless: bool = False, expect_json: bool = False):
        if cmd is None: cmd = []
        if isinstance(cmd, str): cmd = [cmd]
        if not isinstance(cmd, list): raise TypeError
        joined_cmd = [" ".join(self.base_cmd + cmd)]
        if headless is False:
            cmd_window = ["cmd.exe", "/c", "start", "cmd", "/k"]
            wsl_wrapper = self.docker_image.docker.wsli.base_cmd
            joined_cmd = [" ".join(["docker"] + self.base_cmd + cmd)]
            real_cmd = cmd_window + wsl_wrapper + joined_cmd
            if expect_json is True:
                real_cmd = cmd_window + wsl_wrapper + joined_cmd + ["--output", "json"]
            log.debug(f"Running: {real_cmd}")
            return subprocess.Popen(real_cmd)
        if headless is True:
            if expect_json is True:
                joined_cmd = joined_cmd + ["--output", "json"]
                output = self.docker_image.docker.run(joined_cmd)
                try:
                    return json.loads(output)
                except json.JSONDecodeError as e:
                    raise RuntimeError(f"Invalid JSON from Azure CLI: {output[:300]}") from e
            return self.docker_image.docker.run(joined_cmd)

if __name__ == "__main__":
    AzureCLI.get_instance(True)
