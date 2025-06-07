import subprocess
import time

import psutil
import requests
from fastapi import FastAPI

app = FastAPI()

@app.get("/init")
def hello():
    return {"message": "Hello from Py311"}

if __name__ == "__main__":
    # Launch the FastAPI server in the background
    proc = subprocess.Popen(
        ["uvicorn", "pywinpty311:app", "--host", "127.0.0.1", "--port", "9001"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)  # give server time to start
    response = requests.get("http://127.0.0.1:9001/init")
    print(response.status_code)
    print(response.json())