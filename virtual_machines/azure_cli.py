import subprocess
import sys
import uuid
from pathlib import Path

from loguru import logger as log

from virtual_machines.docker import DockerImage


# import pywinpty


class AzureCLI:
    instances = {}

    def __init__(self, user: Path):
        self.uuid = uuid.uuid4()
        self.docker_image = DockerImage.get_instance(user, rebuild=True)
        self.image_name = self.docker_image.image_name
        if self.image_name == "user":
            self.dir = self.docker_image.dockerfile_path.parent / "azure_user"
            self.dir.mkdir(exist_ok=True)
            Path(self.dir / "commands").mkdir(parents=True, exist_ok=True)
            self.dir_wsl = self.docker_image.to_wsl_path(self.dir)
            self.base_cmd = [
                "run", "--rm",
                "-v", f"{self.docker_image.dockerfile_parent_path}:/app",
                "-v", f"{self.dir_wsl}:/root/.azure",  # persistent config mount
                "-e", "AZURE_CONFIG_DIR=/root/.azure",  # enforce env var
                "-w", "/app",
                self.image_name
            ]
            # log.debug(self.base_cmd)
            cached_user = self.run(["az account show"], headless=True)
            if "ERROR" in cached_user:
                self.run([], headless=False)
                log.error("Please create a valid user login session with Azure CLI... Ending this session...")
                sys.exit()
            log.success(f"Azure CLI session successfully initialized: {self.uuid}, {self.image_name}")

    def run(self, cmd: list | str = None, headless: bool = False):
        if cmd is None: cmd = []
        if isinstance(cmd, str): cmd = [cmd]
        if not isinstance(cmd, list): raise TypeError
        joined_cmd = [" ".join(self.base_cmd + cmd)]
        if headless is False:
            cmd_window = ["cmd.exe", "/c", "start", "cmd", "/k"]
            wsl_wrapper = self.docker_image.docker.wsli.base_cmd
            joined_cmd = [" ".join(["docker"] + self.base_cmd + cmd)]
            real_cmd = cmd_window + wsl_wrapper + joined_cmd
            log.debug(f"Running: {real_cmd}")
            return subprocess.Popen(real_cmd)
        if headless is True:
            return self.docker_image.docker.run(joined_cmd)

    @classmethod
    def get_instance(cls, user: bool):
        log.debug(cls.instances)
        image_name = "sp"
        if user is True: image_name = "user"
        for key in cls.instances:
            if image_name == key: return cls.instances[key]
        image_path = Path.cwd() / f"Dockerfile.{image_name}"
        instance = cls(image_path)
        cls.instances[image_name] = instance
        return instance


if __name__ == "__main__":
    AzureCLI.get_instance(True)
