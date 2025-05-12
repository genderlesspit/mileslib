import os
import json
import requests
import tempfile
import zipfile
import shutil
from packaging import version

class Github:
    def __init__(self, mileslib, dir: str, quiet: bool = None, token: bool = False):
        self.m = mileslib
        self.dir = dir
        self.quiet = quiet or False
        if self.m.exists("config", "config.json") is True:
            self.repo_url = self.m.config.get("repo_url")
        else:
            self.repo_url = "https://raw.githubusercontent.com/genderlesspit/phazedeck/master"
            self.get("config", "config.json")
        self.token = self.m.config.get("token") if token else None
        self.local_version = self.m.config.get("local_version") or "0.0.0"
        self.remote_config = self.get("config", "config.json", no_save=True)
        self.update = self.Update(self)

    class Update:
        def __init__(self, github):
            self.github = github
            self.m = self.github.m
            self.local_version = self.github.local_version
            self.remote_config = self.github.remote_config

            # Get remote version *after* pulling the remote config
            if not self.remote_config:
                raise ValueError("Remote config is None. Cannot parse.")
            else:
                self.remote_version = self.get_version()

        def get_version(self):
            self.github.m.log.info("Current Github version requested...")
            try:
                configdict = json.loads(self.github.remote_config)
                ver = configdict.get("local_version")
                self.m.log.info(f"Current Github version is {ver}")
                return ver
            except Exception as e:
                self.m.crash(f"Could not retrieve remote version: {e}")

        def check(self):
            if version.parse(self.remote_version) > version.parse(self.local_version):
                self.m.log.info(f"Github release available: {self.remote_version} (current: {self.local_version})")
                return True
            else:
                self.m.log.info("No available updates.")
                return False

        def install_full_update(self):
            try:
                self.m.log.info("Beginning full update from GitHub repository...")

                zip_url = self.github.repo_url.replace("raw.githubusercontent.com", "github.com").replace("/master",
                                                                                                   "/archive/refs/heads/master.zip")
                headers = {"Authorization": f"token {self.github.token}"} if self.github.token else {}

                self.m.close_log()

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

                    self.m.log.info(f"Replacing files in {self.github.dir} with contents from repo...")
                    for item in os.listdir(extracted_path):
                        s = os.path.join(extracted_path, item)
                        d = os.path.join(self.github.dir, item)

                        if os.path.isdir(s):
                            if os.path.exists(d):
                                shutil.rmtree(d)
                            shutil.copytree(s, d)
                        else:
                            shutil.copy2(s, d)

                self.m.open_log()
                self.m.log.info("Full update completed successfully.")
                self.m.restart()

            except Exception as e:
                self.m.crash(f"Full update from GitHub failed: {e}")

    def get(
            self,
            *args: str,  # Path components to append to the URL.
            url: str = None,  # url (str): Base URL to use (default: self.base_url).
            as_text: bool = False,  # Return as text (str) or bytes.
            no_save: bool = False,
            token: bool = False,  # If True, include GitHub token in request headers.
            save_as: str = None,  # If provided, save the file to this local dir.
            quiet: bool = False
    ) -> str | bytes | None:

        base = url or self.repo_url
        if not base:
            self.m.log.warning("No URL provided and no base_url set.")
            return None
        self.m.log.info(f"Base Github URL Called: {base}...", quiet=quiet)

        full_url = "/".join([base.rstrip("/")] + [arg.strip("/") for arg in args])
        self.m.log.info(f"Assembling request for {full_url}", quiet=quiet)

        local_path = os.path.join(self.dir, *args)
        self.m.log.info(f"Local path acknowledged: {local_path}...")
        headers = {"Authorization": f"token {self.token}"} if token and self.token else {}

        try:
            content = self.m.request(full_url, headers=headers, as_text=as_text, message="Retrieving from Github")
            if content is None:
                return None

            def save():
                def save_to_default_path():
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    mode = "w" if as_text else "wb"
                    with open(local_path, mode, encoding="utf-8" if as_text else None) as f:
                        f.write(content)
                    self.m.log.info(f"Saved to default path: {local_path}")
                    return content

                def save_as_file():
                    try:
                        full_path = os.path.join(self.dir, save_as)
                        os.makedirs(os.path.dirname(full_path), exist_ok=True)
                        mode = "w" if as_text else "wb"
                        with open(full_path, mode, encoding="utf-8" if as_text else None) as f:
                            f.write(content)
                        self.m.log.info(f"Saved to: {full_path}") if quiet is not True else None
                    except Exception as e:
                        self.m.crash(f"Invalid path: {e}", warn_only=True) if quiet is not True else None
                    return content

                return save_as_file() if save_as else save_to_default_path()

            if no_save:
                self.m.log.info(f"Request for {full_url} fulfilled successfully.")
                return content
            else:
                return save()

        except Exception as cannot_get:
            self.m.log.warning(f"Failed to retrieve file from {full_url}: {cannot_get}")
            return None