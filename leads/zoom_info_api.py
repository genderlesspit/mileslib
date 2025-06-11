from dataclasses import dataclass
from functools import cached_property

import requests

@dataclass
class ZoomInfoCredentials:
    username: str
    password: str

class ZoomInfoAPI:
    instances = {}

    def __init__(self, creds: ZoomInfoCredentials):
        self.creds = creds
        self.username = creds.username
        self.password = creds.password
        _ = self.token

    @classmethod
    def new(cls, creds: ZoomInfoCredentials):
        if not creds.username in cls.instances:
            cls.instances[creds.username] = cls(creds)

    @classmethod
    def get(cls, username: str):
        if not username in cls.instances: raise KeyError
        return cls.instances[username]

    @cached_property
    def token(self) -> str:
        url = "https://api.zoominfo.com/authenticate"
        data = {
            "username": self.username,
            "password": self.password
        }
        headers = {
            "Content-Type": "application/json"
        }
        try:
            response = requests.post(url, json=data, headers=headers, timeout=10)
            response.raise_for_status()
            json_data = response.json()
            token = json_data.get("token") or json_data.get("access_token")
            if not token:
                raise ValueError("Authentication succeeded but no token found in response.")
            return token
        except Exception as e:
            raise RuntimeError(f"ZoomInfo API token retrieval failed: {e}")

if __name__ == "__main__":
    dave = ZoomInfoCredentials(username="dave.rupp@phazebreak.com", password="NeiniceKC24$")
    ZoomInfoAPI(dave)