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
