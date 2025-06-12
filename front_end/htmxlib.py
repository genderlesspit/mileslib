import os
import threading
import time
import uuid
from functools import cached_property

import requests
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from loguru import logger as log

class HTMXServer:
    instance = None
    app = FastAPI()

    def __init__(self, _project, host: str, port: int):
        if not isinstance(host, str): raise TypeError
        if not isinstance(port, int): raise TypeError
        self.uuid = uuid.uuid4()
        self.project = _project
        self.host = host
        self.port = port
        _ = self.thread
        _ = self.url
        _ = self.routes
        self.templates = self.project.templates
        log.success(f"HTMX Server successfully initialized: {self.uuid}, speed: {self.test_connection}ms")

    @cached_property
    def url(self):
        return f"http://{self.host}:{self.port}"

    @cached_property
    def meta(self) -> str:
        return f'<script>window.HTMX_SERVER = "{self.url}";</script>'

    @property
    def thread(self):
        thread = threading.Thread(
            target=lambda: uvicorn.run(self.app, host=self.host, port=self.port, log_level="warning"),
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

    @cached_property
    def routes(self):
        routes = self.project.templates.routes
        for name in routes:
            fn = self.project.templates.routes[name]
            if callable(fn):
                self.app.get(f"/{name}")(fn)
                log.debug(f"[HTMX Server] Route '/{name}' initialized.")
        return routes

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
    def get(cls, _project, host, port):
        if cls.instance:
            log.debug(f"[HTMX Server] Already started on {cls.instance.host}:{cls.instance.port}")
            return cls.instance.app
        cls.instance = cls(_project, host, port)
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