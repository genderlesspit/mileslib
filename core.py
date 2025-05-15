import os
from datetime import datetime
import traceback
import json
import logging as log
import subprocess
import sys
import importlib.util
import zipfile
from time import perf_counter
import io
from config import Config
from logger import Log
from github import Github
from testmanager import TestManager

try:
    import hashlib
    import requests
    from packaging import version
except Exception as e:
    log.warning("Did not find external modules!")

class MilesLib:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.dir = os.getcwd()
        self.launch_time = datetime.utcnow()
        self.timestamp = self.launch_time.strftime("%Y-%m-%d_%H-%M-%S")
        self.log = Log(self, dir=self.dir)
        self.log.open_log()
        self.config = Config(self, dir=self.dir)
        self.github = Github(self, dir=self.dir)
        self.test = TestManager(self, dir=self.dir)
        self.test.discover()

    def dependency(self, dep: str, pack: str = None):
        try:
            if importlib.util.find_spec(dep) is None:
                log.warning(f"Module '{dep}' not found. Installing...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pack or dep])
                    log.info(f"'{pack or dep}' installed successfully.")
                except subprocess.CalledProcessError as e:
                    log.error(f"Failed to install {pack or dep}: {e}")
                    raise
            else:
                log.info(f"Module '{dep}' is already installed.")
        except Exception as e:
            self.crash(f"Issue with dependencies: {e}")

    def exists(
            self,
            *args: str,
            disp: str = None,
            quiet: bool = False,
            startup: bool = None,
            create_if_missing: bool = False
    ) -> tuple[str, bool]:

        path = os.path.join(self.dir, *args)
        exists = os.path.exists(path)

        if exists:
            if not quiet:
                log.info(f"{disp or 'Path'} initialized at {path}.")
            return path, True

        # Handle missing path
        if create_if_missing:
            try:
                if "." in os.path.basename(path):
                    # Assume it's a file
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8") as f:
                        f.write("")
                    log.info(f"File created: {path}")
                else:
                    # Assume it's a dir
                    os.makedirs(path, exist_ok=True)
                    log.info(f"Directory created: {path}")
                return path, True
            except Exception as e:
                log.error(f"Failed to create {disp or 'path'}: {e}")
                return path, False
        else:
            if not quiet:
                log.warning(f"{disp or 'Path'} not found at {path}!")
            return path, False

    def crash(self, e: str = None, warn_only: bool = None, quiet: bool = None):
        error_trace = traceback.format_exc()
        self.log.error(f"Crash occurred: {e}", quiet=quiet)

        #try:
        #    log_path = self.log.file
        #    metadata = {
        #        "version": self.config.get("local_version"),
        #        "timestamp": datetime.utcnow().isoformat() + "Z",
        #        "platform": sys.platform,
        #        "exception": str(e) or "No error string provided",
        #        "traceback": error_trace,
        #    }
        #
        #    # Upload crash log
        #    response, info = self.upload(
        #        url="https://your-crash-endpoint.com/report",  # <-- Replace this
        #        filepaths=[log_path],
        #        fields={"metadata": json.dumps(metadata)},
        #        message="Uploading crash report"
        #    )
        #
        #    if response:
        #        log.info("Crash report uploaded successfully.")
        #        log.debug(f"Upload metadata: {json.dumps(info, indent=2)}")
        #    else:
        #        log.warning("Crash report upload failed or returned no response.")
        #
        #

        #except Exception as send_err:
        #    log.warning(f"Failed to send crash report: {send_err}"
        #

        #if warn_only is not True:
        #    raise RuntimeError(f"Program terminated. See log: {log_path}")
        #else:
        #    log.warning("Crash bypassed by function.")

    def request(self, url, method="GET", headers=None, data=None, json_data=None, files=None,
                as_text=True, timeout=(5, 10), retry_on_status=(500, 502, 503, 504), message: str = None):

        def request_fn():
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                data=data,
                json=json_data,
                files=files,
                timeout=timeout
            )
            if response.status_code in retry_on_status:
                raise requests.HTTPError(f"Retryable status: {response.status_code}")
            return response

        response, duration = self.timer(lambda: self.attempt(request_fn, message=message))
        log.info(f"Request to {url} succeeded in {duration:.2f}s with status {response.status_code}")
        return response.text if as_text else response.content

    def is_valid_file_size(self, path: str, max_size_mb: float) -> bool:
        """Check if the file or folder at `dir` is below the size limit."""
        total_size = 0

        if os.path.isfile(path):
            total_size = os.path.getsize(path)
        elif os.path.isdir(path):
            for dirpath, dirnames, filenames in os.walk(path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if os.path.isfile(fp):
                        total_size += os.path.getsize(fp)

        size_mb = total_size / (1024 * 1024)
        log.info(f"Computed size for {path}: {size_mb:.2f} MB")
        return size_mb <= max_size_mb

    @staticmethod
    def compute_sha256(buffer: bytes) -> str:
        """Compute SHA-256 hash of in-memory buffer."""
        hasher = hashlib.sha256()
        hasher.update(buffer)
        return hasher.hexdigest()

    def build_payload(self, filepaths: list[str] = None, dirs: list[str] = None,
                      max_size_mb: float = 10.0, archive_name: str = "data.zip") -> tuple:
        """Zips files and directories into an in-memory archive for upload."""

        log_buffer = io.BytesIO()
        with zipfile.ZipFile(log_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for path in filepaths or []:
                if os.path.isfile(path):
                    if not self.is_valid_file_size(path, max_size_mb):
                        raise ValueError(f"File exceeds {max_size_mb}MB: {path}")
                    zipf.write(path, arcname=os.path.basename(path))
                else:
                    log.warning(f"Skipping invalid file: {path}")

            for folder in dirs or []:
                if os.path.isdir(folder):
                    if not self.is_valid_file_size(folder, max_size_mb):
                        raise ValueError(f"Directory exceeds {max_size_mb}MB: {folder}")
                    for root, _, files in os.walk(folder):
                        for file in files:
                            abs_path = os.path.join(root, file)
                            rel_path = os.path.relpath(abs_path, start=folder)
                            arcname = os.path.join(os.path.basename(folder), rel_path)
                            zipf.write(abs_path, arcname=arcname)
                else:
                    log.warning(f"Skipping invalid directory: {folder}")

        log_buffer.seek(0)
        archive_bytes = log_buffer.getvalue()
        hash_value = self.compute_sha256(archive_bytes)
        size_kb = round(len(archive_bytes) / 1024, 2)

        files = {
            'archive': (archive_name, io.BytesIO(archive_bytes), 'application/zip')
        }
        metadata = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "archive_name": archive_name,
            "archive_size_kb": size_kb,
            "sha256": hash_value
        }

        return files, metadata

    def upload(self, url: str, filepaths: list[str] = None, dirs: list[str] = None, fields: dict = None,
               headers: dict = None, max_size_mb: float = 10.0, message: str = None) -> tuple[str, dict] | None:
        """Uploads zipped files/dirs via POST. Returns (response_text, metadata) or None."""
        try:
            files, metadata = self.build_payload(filepaths=filepaths, dirs=dirs, max_size_mb=max_size_mb)
            response = self.request(
                url=url,
                method="POST",
                headers=headers,
                data=fields,
                files=files,
                as_text=True,
                message=message or "Uploading data"
            )
            return response, metadata
        except Exception as e:
            log.error(f"Upload failed: {e}")
            return None

if __name__ == "__main__":
    #Miles Lib Instance
    m = MilesLib()