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
            self.repo_url = self.m.config.get("repo_url", )
        else:
            self.repo_url = "https://raw.githubusercontent.com/genderlesspit/phazedeck/master"
            self.get("config", "config.json")
        self.token = self.m.config.get("token", ) if token else None
        self.local_version = self.m.config.get("local_version", ) or "0.0.0"
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
                ver = configdict.get("local_version", )
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

        class Github:
            @staticmethod
            def get_file(
                    mileslib,
                    *path_parts: str,
                    repo_url: str,
                    dest_dir: Path,
                    as_text: bool = True,
                    save_as: str = None,
                    token: str = None,
                    quiet: bool = False,
                    no_save: bool = False,
            ) -> str | bytes | None:
                """
                Fetch a file from GitHub and optionally save it locally.

                Args:
                    mileslib: MilesLib instance for logging and requests
                    path_parts: Path components (e.g., "config", "config.json")
                    repo_url: Base GitHub URL
                    dest_dir: Where to save the file (default: assembled from path_parts)
                    as_text: Return as string if True, else bytes
                    save_as: Optional name to save as
                    token: GitHub access token (optional)
                    quiet: Suppress logging
                    no_save: If True, return content without writing to disk

                Returns:
                    Content as str or bytes if `no_save` is True, otherwise saved content
                """
                full_url = "/".join([repo_url.rstrip("/")] + [p.strip("/") for p in path_parts])
                local_path = dest_dir / (save_as or os.path.join(*path_parts))

                headers = {"Authorization": f"token {token}"} if token else {}

                try:
                    content = mileslib.request(full_url, headers=headers, as_text=as_text,
                                               message="Downloading from GitHub")
                    if content is None:
                        return None

                    if no_save:
                        return content

                    # Save to disk
                    os.makedirs(local_path.parent, exist_ok=True)
                    mode = "w" if as_text else "wb"
                    with open(local_path, mode, encoding="utf-8" if as_text else None) as f:
                        f.write(content)
                    mileslib.log.info(f"Saved GitHub file to {local_path}")
                    return content

                except Exception as e:
                    mileslib.log.warning(f"Failed to retrieve from GitHub: {e}")
                    return None

            @staticmethod
            def get_remote_config(mileslib, repo_url: str, token: str = None) -> dict:
                """
                Fetch remote config.json from GitHub and parse as JSON.

                Returns:
                    Parsed JSON dictionary
                """
                raw = StaticMethods.Github.get_file(
                    mileslib,
                    "config", "config.json",
                    repo_url=repo_url,
                    dest_dir=Path(mileslib.pdir) / "config",
                    as_text=True,
                    token=token,
                    no_save=True
                )
                try:
                    return json.loads(raw)
                except Exception as e:
                    mileslib.crash(f"Could not load remote config.json: {e}")
                    return {}

            @staticmethod
            def check_version_update(local_version: str, remote_version: str, mileslib=None) -> bool:
                """
                Compare two versions using PEP 440 rules.

                Returns:
                    True if remote_version is newer than local_version
                """
                if mileslib:
                    mileslib.log.info(f"Comparing local {local_version} vs remote {remote_version}")
                return version.parse(remote_version) > version.parse(local_version)

            @staticmethod
            def install_full_update(mileslib, repo_url: str, dest_dir: Path, token: str = None):
                """
                Downloads and extracts the full repo into `dest_dir`.
                """
                zip_url = repo_url.replace("raw.githubusercontent.com", "github.com").replace(
                    "/master", "/archive/refs/heads/master.zip"
                )
                headers = {"Authorization": f"token {token}"} if token else {}

                try:
                    mileslib.close_log()
                    response = requests.get(zip_url, headers=headers, stream=True)
                    response.raise_for_status()

                    with tempfile.TemporaryDirectory() as tmpdir:
                        zip_path = Path(tmpdir) / "repo.zip"
                        with open(zip_path, "wb") as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                f.write(chunk)

                        with zipfile.ZipFile(zip_path, "r") as zip_ref:
                            zip_ref.extractall(tmpdir)

                        repo_root = next(Path(tmpdir).glob("*/"))
                        for item in repo_root.iterdir():
                            target = dest_dir / item.name
                            if item.is_dir():
                                if target.exists():
                                    shutil.rmtree(target)
                                shutil.copytree(item, target)
                            else:
                                shutil.copy2(item, target)

                    mileslib.open_log()
                    mileslib.log.info("✅ GitHub update complete. Restarting...")
                    mileslib.restart()

                except Exception as e:
                    mileslib.crash(f"Update failed: {e}")