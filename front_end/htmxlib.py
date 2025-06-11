import json
import threading
import time

import requests
import uvicorn
from fastapi import FastAPI
from starlette.responses import HTMLResponse, JSONResponse

from loguru import logger as log

class Routes:
    def hello(self): return {"msg": "Hello"}
    def goodbye(self): return {"msg": "Goodbye"}

class Server:
    _started = False
    app = FastAPI()
    routes = Routes()

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

    @classmethod
    def get(cls):
        if cls._started: return cls.app
        cls._started = True
        threading.Thread(target=lambda: uvicorn.run(cls.app, host="127.0.0.1", port=6969, log_level="warning"), daemon=True).start()
        for _ in range(10):
            try:
                health = requests.get("http://127.0.0.1:6969/healthz").status_code
                log.debug(health)
                if health == 200: break
            except: time.sleep(0.2)
        return cls.app

    @staticmethod
    def request(route: str):
        domain = "http://127.0.0.1:6969"
        url = domain + route
        response = requests.get(url).content
        if response is JSONResponse: response = json.load(response)
        log.debug(response)
        return response

if __name__ == "__main__":
    Server.get()
    Server.request("/hello")