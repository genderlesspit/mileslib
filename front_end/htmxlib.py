import os
import requests
import threading
import time
import uuid
import uvicorn
from functools import cached_property

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from loguru import logger as log

class Templates:
    pass


class Routes:
    def _hello(self): return JSONResponse({"msg": "test"})


class Server:
    instance = None
    app = FastAPI()
    routes = Routes()

    def __init__(self, host: str, port: int):
        if not isinstance(host, str): raise TypeError
        if not isinstance(port, int): raise TypeError
        self.uuid = uuid.uuid4()
        self.host = host
        self.port = port
        _ = self.thread
        _ = self.url
        log.success(f"HTMX Server successfully initialized: {self.uuid}, speed: {self.test_connection}ms")

    @cached_property
    def url(self):
        return f"http://{self.host}:{self.port}"

    @property
    def thread(self):
        thread = threading.Thread(target=lambda: uvicorn.run(self.app, host=self.host, port=self.port, log_level="warning"),
                         daemon=True)
        if not thread.is_alive():
            log.warning("[HTMX Server] Server not found... Launching...")
            thread.start()
            if not thread.is_alive(): raise RuntimeError
        return

    @property
    def test_connection(self):
        response = None
        for _ in range(10):
            try:
                start = time.perf_counter()
                response = requests.get(f"{self.url}/healthz", timeout=0.2)
                elapsed = (time.perf_counter() - start) * 1000
                if response.status_code == 200:
                    log.debug(f"[HTMX Server] Connection secured in {elapsed:.2f} ms")
                    return elapsed
            except:
                time.sleep(0.05)  # 50ms backoff
        raise ConnectionError

    for name in dir(routes):
        if not name.startswith("_"):
            fn = getattr(routes, name)
            if callable(fn):
                app.get(f"/{name}")(fn)
                log.debug(f"[HTMX Server] Route '/{name}' initialized.")

    @staticmethod
    @app.get("/")
    def root():
        return JSONResponse({"message": "Hello FastAPI!"})

    @staticmethod
    @app.get("/healthz")
    def healthz():
        return JSONResponse({"status": "ok"})

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
        try:
            response = requests.post("http://127.0.0.1:6969/shutdown")
            return log.debug(response.status_code)
        except Exception:
            pass

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