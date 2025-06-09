from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from loguru import logger as log

import toml


class Server:
    instance = None

    def __init__(self, path: Path):
        self.project_path = path

        _ = self.server_cache

    @classmethod
    def get_instance(cls, path):
        if cls.instance is None:
            cls.instance = cls(path)
        return cls.instance

    @cached_property
    def server_cache(self) -> dict:
        server_cache_path = self.project_path / "cache" / "server_cache.toml"
        data = toml.load(server_cache_path)
        return data

    @dataclass
    class AppConfig:
        app_name: str
        docker_image: str
        app_service_name: str
        dns_name: str
        redirect_uri: str
        allowed_origins: list[str]
        storage_account_name: str
        container_registry_name: str
        certificate_name: str

    @cached_property
    def app_config(self):
        return Server.AppConfig(**self.server_cache["app_config"])

    @dataclass
    class AzureUser:
        tenant_id: str

    @cached_property
    def azure_user(self):
        return Server.AzureUser(**self.server_cache["azure_user"])

    @dataclass
    class ServicePrincipal:
        client_id: str
        client_secret: str

    @cached_property
    def service_principal(self):
        return Server.ServicePrincipal(**self.server_cache["service_principal"])

    @dataclass
    class AzureResourceManager:
        resource_group: str
        region: str

    @cached_property
    def azure_resource_group(self):
        return Server.AzureResourceManager(**self.server_cache["azure_resource_group"])

    @dataclass
    class GraphAPI:
        authority_url: str
        scopes: list[str]

    @dataclass
    class ZoomInfoAPI:
        api_key: str
        base_url: str
        rate_limit_per_minute: int

    @dataclass
    class DatabaseConfig:
        db_name: str
        db_user: str
        db_password: str
        db_firewall_ip: str
        connection_string: str

    # @dataclass
    # class Monitoring:
    #    app_insights_name: str
    #    log_analytics_workspace: str

if __name__ == "__main__":
    path = Path.cwd().parent
    myla = Server.get_instance(path)
    log.debug(myla.server_cache)
