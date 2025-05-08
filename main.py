import os
from datetime import datetime
import traceback
import json
import logging as log
import subprocess
import sys
import importlib.util
import tempfile
import zipfile
import shutil
from time import perf_counter
import io

try:
    import hashlib
    import requests
    from packaging import version
except Exception as e:
    log.warning("Did not find external modules!")

class Main:
    def __init__(self, dir: str = None):
        #Initialize Logging
        log.basicConfig(
            level=log.INFO,
            format='%(asctime)s - MILESLIB - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        log.info("Logging initialized.")

        #Initialize Project Directory
        self.dir = dir or os.getcwd()
        log.info(f"Directory Initialized: {self.dir}")
        self.launchtime = datetime.now().strftime("%Y-%m-%d.%H-%M-%S")
        log.info(f"Launch Time Initialized: {self.launchtime}")

        #Config Setup
        self.config_startup = self.Config(self, on_startup=True)
        self.config = self.Config(self, quiet=True)

        #Ensure setup
        self.setup_status = self.config_startup.get("setup_complete")
        if not self.setup_status is True:
            raise RuntimeError(f"Setup not complete! 'setup_complete' in 'config.json' is {self.setup_status}. It must be set to 'True' to continue.")

        self.rdir = self.config_startup.get("directories", "folder")

        #Create Session Log
        self.logdir = os.path.join(self.rdir, self.config.get("directories", "logs"))
        os.makedirs(self.logdir, exist_ok=True)
        log.info(f"Log Directory: {self.logdir}")

        self.filename = f"{self.launchtime}.txt"
        self.logfiledir = os.path.join(self.logdir, f"{self.filename}")
        open(self.logfiledir, "w", encoding="utf-8")
        log.info(f"Successfully created {self.logfiledir}")

        #Create Quiet Config

        #Log Handler
        file_handler = log.FileHandler(self.logfiledir, encoding="utf-8")
        file_handler.setFormatter(log.Formatter(
            fmt='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        log.getLogger().addHandler(file_handler)
        log.info("FileHandler attached: all logs will now write to the log file.")

        #Github Handler
        self.github = self.Github(self)
        log.info(f"Acknowledged local version: {self.github.local_version}")
        self.github.check(full_update=True) #Check for Updates

        #Ensure code.json exists
        self.code_json_dir = os.path.join(self.dir, self.config.get("directories", "code.json"))
        os.path.exists(self.code_json_dir)

        #Flask Setup
        #self.flask()

    #Utility functions

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

    def dir_exists(self, dir: str, quiet: bool = None, startup: bool = None):
        if startup is True:
            rdir = os.path.join(self.dir, dir)
        else:
            rdir = os.path.join(self.rdir, dir) #rdir stands for "real directory"
        if os.path.exists(rdir):
            if not quiet:
                log.info(f"{dir} initialized at {rdir}.")
            return True
        else:
            try:
                os.makedirs(rdir, exist_ok=True)
            except Exception as e:
                self.crash(f"Could not create {rdir}: {e}")

    def file_exists(self, *args: str, disp: str = None, quiet: bool = None, startup: bool = None):
        if startup is True:
            path = os.path.join(self.dir, *args)
        else:
            path = os.path.join(self.rdir, *args)
        if os.path.exists(path):
            if not quiet:
                if disp:
                    log.info(f"{disp} initialized at {path}.")
                else:
                    log.info(f"File initialized at {path}.")
            return True
        else:
            if not quiet:
                if disp:
                    log.warning(f"{disp} not found at {path}!")
                else:
                    log.warning(f"No file found at {path}!")
            return False

    def crash(self, e: str = None, warn_only: bool = None, quiet: bool = None):
        error_trace = traceback.format_exc()
        log.error(error_trace if not quiet else f"Crash occurred: {e}")

        try:
            log_path = self.logfiledir
            metadata = {
                "version": self.config.get("local_version"),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "platform": sys.platform,
                "exception": str(e) or "No error string provided",
                "traceback": error_trace
            }

            # Upload crash log
            response, info = self.upload(
                url="https://your-crash-endpoint.com/report",  # <-- Replace this
                filepaths=[log_path],
                fields={"metadata": json.dumps(metadata)},
                message="Uploading crash report"
            )

            if response:
                log.info("Crash report uploaded successfully.")
                log.debug(f"Upload metadata: {json.dumps(info, indent=2)}")
            else:
                log.warning("Crash report upload failed or returned no response.")

        except Exception as send_err:
            log.warning(f"Failed to send crash report: {send_err}")

        if warn_only is not True:
            raise RuntimeError(f"Program terminated. See log: {self.logfiledir}")
        else:
            log.warning("Crash bypassed by function.")

    def restart(self):
        log.info("Restarting application...")
        python = sys.executable
        os.execv(python, [python] + sys.argv)

    def close_log(self):
        logger = log.getLogger()
        for handler in logger.handlers[:]:
            if isinstance(handler, log.FileHandler):
                handler.close()
                logger.removeHandler(handler)

    def open_log(self):
        file_handler = log.FileHandler(self.logfiledir, encoding="utf-8")
        file_handler.setFormatter(log.Formatter(
            fmt='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        log.getLogger().addHandler(file_handler)

    def timer(self, fn, *args, **kwargs):
        start = perf_counter()
        result = fn(*args, **kwargs)
        duration = perf_counter() - start
        log.info(f"Execution time: {duration:.2f}s")
        return result, duration

    def attempt(self, fn, max_retries=3, backoff=2, retry_on=Exception, delay_func=None, message: str=None):
        import time

        for attempt_num in range(1, max_retries + 1):
            try:
                logmsg = f"Attempt {attempt_num}..."
                log.info(f"{message}: {logmsg}") if message else log.info(f"{logmsg}")
                return fn()
            except retry_on as e:
                log.warning(f"Attempt {attempt_num} failed: {e}")
                if attempt_num < max_retries:
                    wait = delay_func(attempt_num) if delay_func else backoff * attempt_num
                    log.info(f"Retrying in {wait} seconds...")
                    time.sleep(wait)
                else:
                    log.error(f"All {max_retries} attempts failed.")
                    raise

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
        """Check if the file or folder at `path` is below the size limit."""
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
        hash_value = compute_sha256(archive_bytes)
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

    class Github:
        def __init__(self, main, quiet: bool = None, startup: bool = False):
            self.main = main
            self.update = self.Update(self)
            self.quiet = quiet or False
            self.repo_url = self.main.config.get("repo_url")
            self.token = self.main.config.get("token")
            self.local_version = self.main.config.get("local_version") or "0.0.0"
            self.remote_config = self.get("config", "config.json", no_save=True)

            # Get remote version *after* pulling the remote config
            if not self.remote_config:
                raise ValueError("Remote config is None. Cannot parse.")
            else:
                self.remote_version = self.update.get_version()

        class Update:
            def __init__(self, github):
                self.main = github

            def get_version(self):
                log.info("Current Github version requested...")
                try:
                    configdict = json.loads(self.main.remote_config)
                    ver = configdict.get("local_version")
                    log.info(f"Current Github version is {ver}")
                    return ver
                except Exception as e:
                    self.main.main.crash(f"Could not retrieve remote version: {e}")

            def check(self):
                if version.parse(self.main.remote_version) > version.parse(self.main.local_version):
                    log.info(f"Github release available: {self.main.remote_version} (current: {self.main.local_version})")
                    return True
                else:
                    log.info("No available updates.")
                    return False

        def get(
                self,
                *args: str, #Path components to append to the URL.
                url: str = None,  # url (str): Base URL to use (default: self.base_url).
                as_text: bool = True, #Return as text (str) or bytes.
                no_save: bool = False,
                token: bool = False, #If True, include GitHub token in request headers.
                save_as: str = None, #If provided, save the file to this local path.
                quiet: bool = False
        ) -> str | bytes | None:

            base = url or self.repo_url
            if not base:
                log.warning("No URL provided and no base_url set.")
                return None
            log.info(f"Base Github URL Called: {base}...") if quiet is not True else None

            full_url = "/".join([base.rstrip("/")] + [arg.strip("/") for arg in args])
            log.info(f"Assembling request for {full_url}") if quiet is not True else None

            local_path = os.path.join(self.main.dir, *args)
            log.info(f"Local path acknowledged: {local_path}...") if quiet is not True else None
            headers = {"Authorization": f"token {self.token}"} if token and self.token else {}

            try:
                content = self.main.request(full_url, headers=headers, as_text=as_text, message="Retrieving from Github")
                if content is None:
                    return None

                def save():
                    def save_to_default_path():
                        os.makedirs(os.path.dirname(local_path), exist_ok=True)
                        mode = "w" if as_text else "wb"
                        with open(local_path, mode, encoding="utf-8" if as_text else None) as f:
                            f.write(content)
                        log.info(f"Saved to default path: {local_path}") if quiet is not True else None
                        return content

                    def save_as_file():
                        try:
                            full_path = os.path.join(self.main.dir, save_as)
                            os.makedirs(os.path.dirname(full_path), exist_ok=True)
                            mode = "w" if as_text else "wb"
                            with open(full_path, mode, encoding="utf-8" if as_text else None) as f:
                                f.write(content)
                            log.info(f"Saved to: {full_path}") if quiet is not True else None
                        except Exception as e:
                            self.main.crash(f"Invalid path: {e}", warn_only=True) if quiet is not True else None
                        return content

                    return save_as_file() if save_as else save_to_default_path()

                if no_save:
                    log.info(f"Request for {full_url} fulfilled successfully.")
                    return content
                else:
                    return save()

            except Exception as cannot_get:
                log.warning(f"Failed to retrieve file from {full_url}: {cannot_get}")
                return None

        def check(self, *args, update: bool = False, full_update: bool = False):
            can_full_update = self.update.check()
            def install_full_update():
                try:
                    log.info("Beginning full update from GitHub repository...")

                    zip_url = self.repo_url.replace("raw.githubusercontent.com", "github.com").replace("/master","/archive/refs/heads/master.zip")
                    headers = {"Authorization": f"token {self.token}"} if self.token else {}

                    self.main.close_log()

                    response = requests.get(zip_url, headers=headers, stream=True)
                    response.raise_for_status()

                    with tempfile.TemporaryDirectory() as tempdir:
                        zip_path = os.path.join(tempdir, "repo.zip")
                        with open(zip_path, "wb") as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                f.write(chunk)

                        with zipfile.ZipFile(zip_path, "r") as zip_ref:
                            zip_ref.extractall(tempdir)

                        repo_dir_name = next(
                            name for name in os.listdir(tempdir) if os.path.isdir(os.path.join(tempdir, name)))
                        extracted_path = os.path.join(tempdir, repo_dir_name)

                        log.info(f"Replacing files in {self.main.dir} with contents from repo...")
                        for item in os.listdir(extracted_path):
                            s = os.path.join(extracted_path, item)
                            d = os.path.join(self.main.dir, item)

                            if os.path.isdir(s):
                                if os.path.exists(d):
                                    shutil.rmtree(d)
                                shutil.copytree(s, d)
                            else:
                                shutil.copy2(s, d)

                    self.main.open_log()
                    log.info("Full update completed successfully.")
                    self.main.restart()

                except Exception as e:
                    self.main.crash(f"Full update from GitHub failed: {e}")

            install_full_update() if can_full_update is True else None

    class Config:
        def __init__(self, main, dir: str = None, on_startup: bool = None, quiet: bool = None):
            self.main = main
            self.quiet = quiet or False
            try:
                #Directory setup
                self.cdir = dir or "config"
                self.main.dir_exists(f"{self.cdir}", quiet=self.quiet, startup=True)
                self.config_dir = os.path.join(f"{self.main.dir}", f"{self.cdir}", "config.json")

                #Default config settings
                if not self.main.file_exists(f"{self.cdir}", "config.json", disp="config.json", quiet=self.quiet, startup=True ):
                    dconfig = {
                        "setup_complete": True,
                        "local_version": "0.0.0",
                        "repo_url": "https://raw.githubusercontent.com/genderlesspit/phazedeck/master",
                        "token": "",
                        "dependencies": {
                            "flask": {
                                "dep": "flask",
                                "pack": "flask"
                            },
                            "requests": {
                                "dep": "requests",
                                "pack": "requests"
                            },
                            "packaging": {
                                "dep": "packaging",
                                "pack": "packaging"
                            }
                        },
                        "directories": {
                            "folder": "C:\\Users\\miles\\PycharmProjects\\ColdEmailer",
                            "logs":"logs",
                            "code.json": "config\\code_template.json"
                        }
                    }
                    with open(self.config_dir, "w", encoding="utf-8") as f:
                        json.dump(dconfig, f, indent=4)
                        log.info(f"Config file created at {self.cdir}")

                #Startup Settings
                else:
                    if on_startup is True:
                        log.info("MilesLib config settings appear to be in working order... Let's check...")
                        self.check("dependencies")
                        self.install_all_dependencies()
                        self.check("directories")
                        log.info("Config startup complete!")
                    else:
                        pass
            except Exception as e:
                self.main.crash(f"{e}")

        def install_all_dependencies(self):
            try:
                deps = self.get("dependencies")
                if not isinstance(deps, dict):
                    log.warning("No dependencies found in config.")
                    return

                for name, entry in deps.items():
                    dep = entry.get("dep")
                    pack = entry.get("pack", dep)

                    if dep:
                        log.info(f"Initializing dependency: {name} (import: '{dep}', pip: '{pack}')")
                        self.main.dependency(dep.strip(), pack.strip() if pack else dep.strip())
                    else:
                        log.warning(f"Skipping dependency '{name}' — missing 'dep' key.")

            except Exception as e:
                self.main.crash(f"Issue with dependency retrieval: {e}")

        def check(self, *args: str):
            try:
                with open(self.config_dir, "r", encoding="utf-8") as f:
                    config_data = json.load(f)

                #Scroll Through Data
                current = config_data
                for key in args:
                    if isinstance(current, dict) and key in current:
                        current = current[key]
                    else:
                        log.warning(f"Missing config key: {' -> '.join(args)}")
                        return False
                log.info(f"Config value found for {' -> '.join(args)}: {current}")
                return True

            except Exception as e:
                self.main.crash(f"Config reading went wrong!: {e}")

        def get(self, *args: str):
            try:
                with open(self.config_dir, "r", encoding="utf-8") as f:
                    config_data = json.load(f)

                #Scroll Through Data
                current = config_data
                for key in args:
                    if isinstance(current, dict) and key in current:
                        current = current[key]
                    else:
                        return None  # Key path not found
                return current  # Final value

            except Exception as e:
                self.main.crash(f"Retrieving config setting went wrong!: {e}")

    def code_template(self):
        pass

    def flask(self):
        try:
            self.dir_exists(dir="flask")
            self.flask_app_dir = os.path.join(self.dir, "flask", "flask.py")
            #Check for existence of Flask App
            self.flask_exists = self.file_exists("flask", "flask.py")
            if not self.flask_exists:
                with open(self.flask_app_dir, "w", encoding="utf-8") as f:
                    f.write("#MilesLib Flask App")
                    log.info("Flask app successfully created.")
            else:
                log.info("Flask app already exists.")

        except Exception as e:
            self.crash(f"{e}")

class Modules:
    def __init__(self, modules_dir: str, main):
        # Initialize Modules
        #try:
        #    self.modules_dict = {}
        #    files = os.listdir(modules_dir)
        #    for file in files:
        #        self.dir = os.path.join(modules_dir, file)
        #        with open(self.dir, "r", encoding="utf-8") as f:
        #            text = f.read()
        #            log.info(f"Storing {file} in dictionary:")
        #            log.info(f"{text}")
        #            module_name = file.replace(".txt", "")
        #            self.modules_dict[module_name] = Template(text)
        #except Exception as e:
        #    main.crash(f"{e}")
        self.modules_json = os.path.join(modules_dir, "modules.json")
        try:
            with open(self.modules_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                log.info(data)
        except Exception as e:
            main.crash(f"{e}")

    #def load_lead_data(self, file_path: str):
    #    try:
    #        df = pd.read_excel(file_path)  # importing excel data
    #        return df
    #    except Exception as e:
    #       main.crash(f"{e}")

    #def assemble_email(self, lead_data: dict):
    #    opener = self.modules_dict["opener"].render(**lead_data)
    #    body = self.modules_dict["body"].render(**lead_data)
    #    signature = self.modules_dict["signature"].render(**lead_data)
    #    email = opener + "\n\n" + body + "\n\n" + signature
    #    return email

if __name__ == "__main__":
    mdir = os.getcwd()
    main = Main(f"{mdir}")
    #modules = Modules("modules", Main)
    #leads = modules.load_lead_data("leads.xlsx")

    #for idx, lead in leads.iterrows():
    #    email = modules.assemble_email(lead.to_dict())
    #    print(email)