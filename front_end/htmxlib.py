import os
import threading, time, requests, json, logging, uvicorn
from functools import cached_property

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from loguru import logger as log

class Routes:
    def hello(self): return JSONResponse({"msg": "Hello"})
    def goodbye(self): return JSONResponse({"msg": "Goodbye"})

class Server:
    instance = None
    app = FastAPI()
    routes = Routes()

    def __init__(self, host: str, port: int):
        if not isinstance(host, str): raise TypeError
        if not isinstance(port, int): raise TypeError
        self.host = host
        self.port = port
        threading.Thread(target=lambda: uvicorn.run(self.app, host=self.host, port=self.port, log_level="warning"),
                         daemon=True).start()
        _ = self.url
        _ = self.test_connection

    @cached_property
    def url(self):
        return f"http://{self.host}:{self.port}"

    @property
    def test_connection(self):
        response = None
        for _ in range(10):
            try:
                response = requests.get(f"{self.url}/healthz")
                if response.status_code == 200: break
            except:
                time.sleep(0.2)
        if response is None: raise ConnectionError
        return response.status_code

    for name in dir(routes):
        if not name.startswith("_"):
            fn = getattr(routes, name)
            if callable(fn):
                app.get(f"/{name}")(fn)

    @staticmethod
    @app.get("/")
    def root(): return JSONResponse({"message": "Hello FastAPI!"})

    @staticmethod
    @app.get("/healthz")
    def healthz(): return JSONResponse({"status": "ok"})

    @staticmethod
    @app.post("/shutdown")
    def shutdown():
        threading.Thread(target=lambda: os._exit(0), daemon=True).start()
        return JSONResponse({"status": "shutting down"})

    @classmethod
    def get(cls, host, port):
        if cls.instance:
            log.debug(f"[HTMX Server] Already started on {cls.instance.host}:{cls.instance.port}")
            return cls.instance.app
        cls.instance = cls(host, port)
        return cls.instance

    @classmethod
    def kill(cls):
        if not cls.instance:
            log.warning("[HTMX Server] Kill failed. No server instance running.")
            return
        cls._started = False
        try:
            response = requests.post("http://127.0.0.1:6969/shutdown")
            return log.debug(response.status_code)
        except Exception: pass

    def request(self, route: str):
        url = f"{self.url}{route}"
        try:
            response = requests.get(url)
            log.debug(f"[GET {route} | {response.status_code}]: {response.text}")
            return response.json() if "application/json" in response.headers.get("content-type", "") else response.text
        except Exception as e:
            log.error(f"Request to {route} failed: {e}")
            return None

if __name__ == "__main__":
    server = Server.get("127.0.0.1", 6969)
    log.debug(server)
    log.debug(server.request("/hello"))
    server.kill()
    server.request("/hello")
