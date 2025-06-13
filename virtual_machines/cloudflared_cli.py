import json
import subprocess
import sys
import uuid
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from loguru import logger as log
from virtual_machines.docker import DockerImage
from mileslib_infra import Global


import requests
from functools import cached_property


class DNS:
    instance = None

    def __init__(self, _project, cloudflare_api_token: str):
        self.project = _project
        self.token = cloudflare_api_token
        self.account = self.project.cloudflare_account
        self.zone = self.project.cloudflare_zone
        self.base = "https://api.cloudflare.com/client/v4"
        self.domain = self.project.domain
        self.tunnel_name = f"{self.project.name}_tunnel"
        self.local_url = self.project.views.url
        _ = self.tunnel_name

    @classmethod
    def new(cls, _project, cloudflare_api_token):
        return cls(_project, cloudflare_api_token)

    @classmethod
    def get(cls):
        if not cls.instance:
            raise RuntimeError("DNS not initialized. Use DNS.new(...) first.")
        return cls.instance

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    @cached_property
    def tunnel(self) -> dict:
        url = f"{self.base}/accounts/{self.account}/cfd_tunnel"
        data = {"name": self.tunnel_name, "config_src": "cloudflare"}
        result = requests.post(url, headers=self.headers, json=data).json()
        if not result.get("success"):
            raise RuntimeError(f"Failed to create tunnel: {result}")
        return result["result"]

    @cached_property
    def ingress(self) -> dict:
        url = f"{self.base}/accounts/{self.account}/cfd_tunnel/{self.tunnel['id']}/configurations"
        data = {
            "config": {
                "ingress": [
                    {"hostname": self.fqdn, "service": self.local_url},
                    {"service": "http_status:404"},
                ]
            }
        }
        result = requests.put(url, headers=self.headers, json=data).json()
        if not result.get("success"):
            raise RuntimeError(f"Failed to configure ingress: {result}")
        return result

    @cached_property
    def dns(self) -> dict:
        url = f"{self.base}/zones/{self.zone}/dns_records"
        data = {
            "type": "CNAME",
            "proxied": True,
            "name": self.fqdn,
            "content": f"{self.tunnel['id']}.cfargotunnel.com",
        }
        result = requests.post(url, headers=self.headers, json=data).json()
        if not result.get("success"):
            raise RuntimeError(f"Failed to create DNS record: {result}")
        return result

    @cached_property
    def status(self) -> dict:
        url = f"{self.base}/accounts/{self.account}/cfd_tunnel/{self.tunnel['id']}"
        return requests.get(url, headers=self.headers).json()["result"]

    @cached_property
    def fqdn(self) -> str:
        return f"{self.tunnel_name}.{self.domain}"

    @cached_property
    def tunnel_token(self) -> str:
        return self.tunnel["token"]

class CloudflaredCLI:
    instances = {}
    tunnels = {}

    from mileslib_infra import Project
    def __init__(self, _project: Project):
        self.uuid = uuid.uuid4()
        self.project = _project
        self.dns = self.project.dns
        self.mileslib = self.project.mileslib
        self.docker_image = DockerImage.get_instance(self.path, rebuild=True)
        self.path_wsl = self.docker_image.to_wsl_path(self.path)
        self.dir_wsl = self.docker_image.to_wsl_path(self.dir)
        self.mileslib_dir_wsl = self.docker_image.to_wsl_path(self.mileslib.directory)
        self.image_name = self.docker_image.image_name
        self.metadata = self.init()

    @classmethod
    def get_instance(cls, _project):
        key = _project.name
        if key in cls.instances:
            return cls.instances[key]
        instance = cls(_project)
        cls.instances[key] = instance
        return instance

    @cached_property
    def path(self) -> Path:
        return self.mileslib.directory / "Dockerfile.cloudflared"

    @cached_property
    def dir(self) -> Path:
        d = self.project.path / "cloudflared_config"
        d.mkdir(exist_ok=True)
        (d / "certs").mkdir(parents=True, exist_ok=True)
        return d

    @cached_property
    def base_cmd(self) -> list:
        env = [
            "run",
            "-v", f"{self.dir_wsl}:/root/.cloudflared",
            "-v", f"{self.mileslib_dir_wsl}:/app",
            "-w", "/app",
            "-e", "HOME=/root",
            "-e", "CLOUDFLARED_HOME=/root/.cloudflared",
            "cloudflared"
        ]
        return env

    def init(self):
        try:
            result = self.run(["--version"], headless=True)
            self.login()
        except Exception as e:
            log.error("Cloudflared container failed to start")
            raise
        log.success(f"Cloudflared session initialized: {self.uuid}")
        return result

    def login(self):
        output = self.run(["tunnel", "list"], headless=True)
        if "ERR Cannot determine default origin" in output:
            self.run(["tunnel", "login"], headless=False)
            log.error("Please create a valid user login session with Cloudflared CLI... Ending this session...")
            sys.exit()

    def start(self, headless: bool = False):
        """
        Run a named Cloudflare tunnel using a token. This is the final step
        after provisioning DNS and ingress remotely via the API.
        """
        token = self.dns.tunnel_token
        if not token or not isinstance(token, str):
            raise ValueError("Tunnel token must be a non-empty string.")

        cmd = ["tunnel", "--token", token]
        return self.run(cmd, headless=headless)

    def run(self, cmd: list | str = None, headless: bool = False, expect_json: bool = False):
        if cmd is None: cmd = []
        if isinstance(cmd, str): cmd = [cmd]
        if not isinstance(cmd, list): raise TypeError
        joined_cmd = [" ".join(self.base_cmd + cmd)]

        if headless is False:
            wsl_cmd = self.docker_image.docker.wsli.base_cmd
            cmd_window = ["cmd.exe", "/c", "start", "cmd", "/k"]
            real_cmd = cmd_window + wsl_cmd + [" ".join(["docker"] + self.base_cmd + cmd)]
            return subprocess.Popen(real_cmd)

        if expect_json is True:
            output = self.docker_image.docker.run(joined_cmd)
            try:
                return json.loads(output)
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Invalid JSON from cloudflared: {output[:300]}") from e

        return self.docker_image.docker.run(joined_cmd)
