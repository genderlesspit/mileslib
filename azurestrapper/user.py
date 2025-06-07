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

        self.graph_client = GraphAPI.get_instance(self.graph_token)

    @classmethod
    def get_instance(cls, project):
        if cls.instance is None:
            cls.instance = cls(project)
        return cls.instance