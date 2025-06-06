import os
import subprocess
import pywinpty

from loguru import logger as log
from virtual_machines.docker import DockerImage
from pathlib import Path

class AzureCLI:
    instances = {}

    def __init__(self, user: Path):
        self.docker_image = DockerImage.get_instance(user, rebuild=True)
        self.pty = pywinpty.PTY()
        self.image_name = self.docker_image.image_name
        if self.image_name == "user":
            self.dir = self.docker_image.dockerfile_path.parent / "azure_user"
            self.dir.mkdir(exist_ok=True)
            self.base_cmd =  self.docker_image.docker.base_cmd + [
                "run", "-it", "--rm",
                "-v", f"{self.docker_image.dockerfile_parent_path}:/app",
                "-w", "/app",
                "user"
            ]
            log.debug(self.base_cmd)
            output = self.run("az account show", headless=True)
            if "Please run 'az login'" in output:
                self.run(headless=False)
                self.run("az account show", headless=True)

    def run(self, cmd: list | str = None, headless: bool = False):
        if cmd is None: cmd = []
        if isinstance(cmd, str): cmd = [cmd]
        if not isinstance(cmd, list): raise TypeError

        if headless is False:
            cmd_window = ["cmd.exe", "/c", "start", "cmd", "/k"]
            wsl_wrapper = self.docker_image.docker.wsli.base_cmd
            joined_cmd = [" ".join(self.base_cmd + cmd)]
            real_cmd = cmd_window + wsl_wrapper + joined_cmd
            log.debug(f"Running: {real_cmd}")
            return subprocess.Popen(real_cmd)
        if headless is True:
            return self.docker_image.run(cmd)

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