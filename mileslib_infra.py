from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Optional
import json
import re
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import List, Any

import requests
from loguru import logger as log

import toml

from backend_methods.milesrequests import Requests
from virtual_machines.azure_cli import AzureCLI


import mileslib

from dotenv import load_dotenv
import os

class Global:
    instance = None

    def __init__(self, path: Path = None):
        self.path = Path.cwd or path
        _ = self.directory

    @classmethod
    def get_instance(cls, path: Path = None):
        path = path or None
        if cls.instance is None:
            cls.instance = cls(path)
        return cls.instance

    @cached_property
    def directory(self) -> Path:
        directory_path = self.path / ".mileslib"
        directory_path.mkdir(exist_ok=True)
        return directory_path

    @dataclass
    class Project:
        name: str
        path: Path
        cfg_file: Path

    @cached_property
    def projects(self) -> dict[str, Project]:
        projects = {}
        for p in self.path.rglob("*_mileslib_settings.toml"):
            if p.is_file():
                project_name = p.parent.name
                projects[project_name] = Global.Project(
                    name=project_name,
                    folder=p.parent,
                    cfg_file=p
                )
        return projects

    def __postinit__ (self):
        for project_name in self.projects:
            project_info = self.projects[project_name]
            Server.get_instance(**project_info.__dict__)

class Server:
    instance = None

    def __init__(self, name, path, cfg_file):
        self.name = name
        self.path = path
        self.cfg_file = cfg_file

    @classmethod
    def get_instance(cls, path):
        if cls.instance is None:
            cls.instance = cls(path)
        return cls.instance

    @cached_property
    def server_toml(self) -> dict:
        data = toml.load(self.cfg_path)
        return data

    @dataclass
    class ServerConfig:
        name: str
        type: str

    @cached_property
    def server_config(self):
        return Server.ServerConfig(**self.server_toml["server_config"])

    class AzureUser:
        instance = None

        def __init__(self):
            _ = self.metadata

        @classmethod
        def get_instance(cls):
            if cls.instance is None:
                cls.instance = cls()
            return cls.instance

        @cached_property
        def tenant_id(self):
            return self.metadata.tenantId

        @cached_property
        def subscription_id(self):
            return self.metadata.id

        @dataclass
        class Metadata:
            environmentName: str
            homeTenantId: str
            id: str
            isDefault: bool
            managedByTenants: List[str]
            name: str
            state: str
            tenantDefaultDomain: str
            tenantDisplayName: str
            tenantId: str
            user: dict

        @cached_property
        def metadata(self):
            return Server.AzureUser.Metadata(**self.azure_cli.metadata)

        @cached_property
        def azure_cli(self):
            docker_file_path = Path(r"/virtual_machines/Dockerfile.user")
            return AzureCLI.get_instance(image_path=docker_file_path, user=True)

        @dataclass
        class GraphToken:
            accessToken: str
            expiresOn: str
            expires_on: str
            subscription: str
            tenant: str
            tokenType: str

        @cached_property
        def graph_token(self):
            token_metadata = self.azure_cli.run(
            "az account get-access-token --resource https://graph.microsoft.com",
            headless=True,
            expect_json=True)
            return Server.AzureUser.GraphToken(**token_metadata)

    @cached_property
    def azure_user(self):
        return Server.AzureUser.get_instance()

    class GraphAPI:
        instance = None

        def __init__(self, version: str = "v1.0"):
            self.token = Server.AzureUser.get_instance().graph_token.accessToken
            self.version = version.strip("/")

        @classmethod
        def get_instance(cls):
            if cls.instance is None:
                cls.instance = cls()
            return cls.instance

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

    @cached_property
    def graph_api(self):
        return Server.GraphAPI.get_instance()

    class ServicePrincipal:
        instance = None

        def __init__(self):
            self.azure_user = Server.AzureUser.get_instance()
            self.graph_api = Server.GraphAPI.get_instance()
            self.client_id = self.metadata.appId
            self.client_secret = self.metadata.password
            self.tenant_id = self.metadata.tenant
            self.name = self.metadata.displayName

        @classmethod
        def get_instance(cls):
            if cls.instance is None:
                cls.instance = cls()
            return cls.instance

        @dataclass
        class Metadata:
            appId: str
            displayName: str
            password: str
            tenant: str

        @cached_property
        def metadata(self):
            data = self.azure_user.azure_cli.run(f"az ad sp create-for-rbac -n mileslib --role Contributor --scope /subscriptions/{self.azure_user.subscription_id}", headless=True)
            json_match = re.search(r"\{.*\}", data, re.DOTALL)
            if not json_match:raise ValueError("No JSON object found in output.")
            try: parsed_data = json.loads(json_match.group(0))
            except json.JSONDecodeError as e: raise ValueError("Failed to parse JSON content.") from e
            return Server.ServicePrincipal.Metadata(**parsed_data)

    @cached_property
    def service_principal(self):
        return Server.ServicePrincipal.get_instance()

    class AzureResourceGroup:
        instance = None

        def __init__(self):
            self.azure_user = Server.AzureUser.get_instance()
            self.graph_api = Server.GraphAPI.get_instance()
            self.name = Server.get_instance()
            self.rg_name = f"{self.name}-rg"

        @classmethod
        def get_instance(cls):
            if cls.instance is None:
                cls.instance = cls()
            return cls.instance

        @dataclass
        class Metadata:
            pass

        @cached_property
        def metadata(self):
            data = self.azure_user.azure_cli.run(f"az group create -l westus -n {self.rg_name}", headless=True)
            json_match = re.search(r"\{.*\}", data, re.DOTALL)
            if not json_match:raise ValueError("No JSON object found in output.")
            try: parsed_data = json.loads(json_match.group(0))
            except json.JSONDecodeError as e: raise ValueError("Failed to parse JSON content.") from e
            return Server.ServicePrincipal.Metadata(**parsed_data)

    @cached_property
    def azure_resource_group(self):
        return Server.AzureResourceGroup.get_instance()

    @dataclass
    class ZoomInfoAPI:
        api_key: str
        base_url: str
        rate_limit_per_minute: int

    @cached_property
    def zoominfo_api(self):
        return Server.ZoomInfoAPI(**self.server_toml["zoominfo_api"])

    @dataclass
    class KeyVault:
        vault_name: str

    @cached_property
    def key_vault(self):
        return Server.KeyVault(**self.server_toml["key_vault"])

    @dataclass
    class Database:
        db_name: str
        db_user: str
        db_password: str
        db_firewall_ip: str
        connection_string: str

    @cached_property
    def database_config(self):
        return Server.Database(**self.server_toml["database"])
    # @dataclass
    # class Monitoring:
    #    app_insights_name: str
    #    log_analytics_workspace: str

if __name__ == "__main__":
    myla = Server.get_instance(path)
    log.debug(myla.server_toml)
    log.warning(myla.azure_user.metadata)
    log.warning(myla.azure_user.graph_token)
    log.warning(myla.service_principal.metadata)

def main():
    Global()

if __name__ == "__main__":
    main()