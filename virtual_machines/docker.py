import itertools
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from loguru import logger as log

from util.sanitization import Sanitization


class DockerImage:
    instances = {}

    def __init__(self, dockerfile: Path):
        self.dockerfile_path = dockerfile
        self.dockerfile_str = str(dockerfile.resolve())
        self.dockerfile_parent_path = str(self.dockerfile_path.parent.resolve())
        self.image_name = Sanitization.standard(self.dockerfile_str.replace("Docker.", ""))
        #self.base_cmd = #####

        if not self.find_image():
            Docker.build(self.dockerfile, self.image_name)

    def find_image(self) -> bool:
        cmd = ["docker", "images", "--format", "{{.Repository}}", self.image_name]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout.strip()
            if result.returncode != 0 or not output:
                log.warning(f"[DockerImage.find_image] Image '{self.image_name}' not found.")
                return False
            log.info(f"[DockerImage.find_image] Found image '{self.image_name}'.")
            return True
        except Exception as e:
            log.error(f"[DockerImage.find_image] Error checking image: {e}")
            return False

    def build(self):
        cmd = ["docker", "build", "-f", self.dockerfile_path, "-t", self.image_name, self.dockerfile_parent_path]

        log.info(f"[Docker.build] Running command: {' '.join(cmd)}")
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True
            )

            if process.stdout is None:
                raise RuntimeError("Docker build stdout is None!")

            for line in iter(process.stdout.readline, ''):
                print(f"[Docker] {line.strip()}", flush=True)

            process.stdout.close()
            process.wait()

            if process.returncode != 0:
                raise RuntimeError(f"Docker build failed for image: {self.image_name}")

        except Exception as e:
            log.exception(f"[Docker.build] Exception: {e}")
            raise


    @classmethod
    def get_instance(cls, dockerfile: Path):
        if not dockerfile.exists():
            raise FileNotFoundError(f"Dockerfile not found at: {dockerfile}")

        dockerfile_str = str(dockerfile.resolve())
        image_name = Sanitization.standard(dockerfile_str.replace("Docker.", ""))

        if image_name in cls.instances:
            return cls.instances[image_name]
        instance = cls(dockerfile)
        cls.instances[image_name] = instance
        return instance

    def run(self, cmd: list):
        """
        Runs a container from the image with optional args.
        Args:
            *args: Commands to run inside the container (e.g. 'az', 'login')
            interactive: If True, attaches stdin/stdout (like a shell)
            remove: If True, auto-deletes container after run (--rm)
        Returns:
            Exit code of the process
        """
        cmd = self.base_cmd + cmd
        result = Docker.run(cmd)

class Docker:
    instance = None

    def __init__(self):
        self.uuid = uuid.uuid4()
        self.wsli = WSL.get_instance()
        self.base_cmd = ["docker"]
        self.check_docker_ready()
        log.success(f"Docker Instance Initialized: {self.uuid}")

    @classmethod
    def get_instance(cls):
        if cls.instance is None:
            cls.instance = cls()
        return cls.instance

    def run(self, cmd: list):
        if not isinstance(cmd, list): raise TypeError
        real_cmd = self.base_cmd + cmd
        self.wsli.run(real_cmd)
        return self.wsli.run(real_cmd)

    def check_docker_ready(self):
        check_cmd = self.base_cmd + ['version', '--format', '{{.Server.Version}}']
        output = self.wsli.run(check_cmd, ignore_codes=[127, 1])
        if "command not found" in output.lower():
            log.warning("Docker not found inside WSL. Installing...")
            try:
                self.wsli.looper(self.wsli.INSTALL_CMDS)
                return True
            except Exception:
                raise RuntimeError("Error in docker installation process!")
        if "docker daemon" in output.lower():
            self.wsli.run(["bash", "-c", "pgrep dockerd || nohup dockerd > /var/log/dockerd.log 2>&1 &"])
        for i in range(10):
            try:
                self.wsli.run(["docker", "version", "--format", "{{.Server.Version}}"], ignore_codes=[1], debug=False)
                log.info("[Docker.check_docker_ready] Docker daemon is up!")
                break
            except RuntimeError:
                log.debug(f"[Docker.check_docker_ready] Waiting for Docker daemon... attempt {i + 1}")
                time.sleep(1)
        else:
            raise RuntimeError("Docker daemon failed to start in time.")

class WSL:
    instance = None

    def __init__(self, distro: str = "Debian"):
        self.path = r"C:\Windows\System32\wsl.exe"
        self.uuid = uuid.uuid4()
        self.base_cmd = [self.path]
        self.distro = distro
        self.check_distro(distro)
        self.run_cmd = self.base_cmd + ["-d", self.distro, "--exec", "bash", "-c"]

        #reinit base_cmd
        self.make_default_root()
        self.base_cmd = [
            self.path,            # "C:\\Windows\\System32\\wsl.exe"
            "-d", self.distro,    # "-d Debian"
            "-u", "root",         # <— force root every time
            "--exec", "bash",     # "--exec bash"
            "-c"                  # "-c" so we can pass a single command string
        ]
        #self.passwordless_sudo()
        log.success(f"WSL Instance Initialized: {self.uuid}, {self.distro}")

    @classmethod
    def get_instance(cls):
        if shutil.which("wsl") is None:
            log.warning("WSL is not installed or not in PATH! Attempting install...")
            cls.install_wsl()
            if shutil.which("wsl") is None:
                raise RuntimeError("WSL installation failed or not available on PATH.")
        else:
            log.success("WSL is installed and available")

        if cls.instance is None:
            cls.instance = cls()
        return cls.instance

    def make_default_root(self):
        # 1. The two lines needed in /etc/wsl.conf:
        conf_content = "[user]\ndefault = root\n"

        # 2. Build a bash snippet that writes those lines into /etc/wsl.conf:
        #    -e ensures that "\n" is interpreted as newline in bash
        bash_cmd = f'echo -e "{conf_content}" > /etc/wsl.conf'

        # 3. Build the Windows‐side command that runs bash_cmd as root:
        cmd_write = [
            self.path,        # "C:\\Windows\\System32\\wsl.exe"
            "-d", self.distro,
            "-u", "root",     # run bash as root, so no sudo prompt
            "--exec", "bash", "-c", bash_cmd
        ]

        try:
            subprocess.run(cmd_write, check=True)
            log.info("[WSL.make_default_root] Wrote /etc/wsl.conf → next WSL launches as root.")
        except subprocess.CalledProcessError as e:
            log.error(f"[WSL.make_default_root] Failed to write /etc/wsl.conf: {e}")
            raise

        # 4. Immediately shut down all WSL distros so that wsl.conf takes effect:
        #    'wsl.exe --shutdown' will stop the VM; next wsl call will restart with new settings.
        cmd_shutdown = [self.path, "--shutdown"]
        try:
            subprocess.run(cmd_shutdown, check=True)
            log.info("[WSL.make_default_root] WSL VM shut down. Next launch will respect /etc/wsl.conf.")
        except subprocess.CalledProcessError as e:
            log.error(f"[WSL.make_default_root] Failed to shut down WSL VM: {e}")
            raise

    @staticmethod
    def install_wsl():
        try:
            result = subprocess.run(["wsl", "--install"], check=True)
            log.success("WSL install initiated.")
        except Exception as e:
            log.error("WSL installation failed.")
            raise RuntimeError("WSL installation failed.") from e

    def check_distro(self, distro: str) -> str:
        list_cmd = ["--list", "--quiet"]
        install_cmd =["cmd.exe", "/c", "start", "cmd.exe", "/k", f"wsl --install -d {distro}"]

        def check():
            try:
                listed_distros = self.run(list_cmd)
                if distro in listed_distros:
                    log.info(f"✅ Distro '{distro}' found.")
                else:
                    raise RuntimeError(f"❌ Distro '{distro}' not found.")
            except subprocess.CalledProcessError as e:
                log.error("WSL list command failed.")
                raise RuntimeError("WSL list command failed.") from e

        def _wait_for_enter(flag):
            input()  # Blocks until Enter is pressed
            flag["break"] = True

        def install():
            subprocess.Popen(install_cmd, shell=True)
            log.info("⏳ Waiting for user to finish install... (press Enter to skip wait)")

            flag = {"break": False}
            threading.Thread(target=_wait_for_enter, args=(flag,), daemon=True).start()

            spinner = itertools.cycle(["|", "/", "-", "\\"])

            while True:
                sys.stdout.write(f"\rInstalling... {next(spinner)} Still waiting for '{self.distro}'... ")
                sys.stdout.flush()
                time.sleep(1)

                if flag["break"]:
                    log.warning("⛔ Manual break triggered by Enter.")
                    break

                try:
                    result = subprocess.run(
                        list_cmd,
                        capture_output=True, text=True, check=True, timeout=5
                    )
                    if self.distro.lower() in result.stdout.lower():
                        print(f"\n✅ Distro '{self.distro}' is now installed.")
                        break
                except Exception:
                    pass

        if not isinstance(distro, str):
            raise TypeError("distro must be a string")

        try:
            return distro
        except RuntimeError:
            time.sleep(1)
            log.info("Continuing with Distro Installation...")
            install()
            return distro
        except subprocess.CalledProcessError as e:
            log.error("❌ Failed to check installed distros.")
            log.error("stdout: {}", e.stdout)
            log.error("stderr: {}", e.stderr)
            raise RuntimeError("WSL --list failed. WSL may not be fully set up.") from e

    def delete_distro(self):
        """
        Unregisters (deletes) the WSL distro specified in self.distro.
        """
        try:
            self.run(
                ["--unregister", self.distro],
            )
            log.success(f"✅ Distro '{self.distro}' has been deleted.")
        except subprocess.CalledProcessError as e:
            log.error(f"❌ Failed to delete distro '{self.distro}': {e.stderr.strip()}")
            raise RuntimeError(f"Could not unregister distro '{self.distro}'") from e

    @staticmethod
    def _decode_wsl_output(output_bytes: bytes) -> str:
        """
        Decode bytes returned from WSL, removing nulls and noise.
        """
        try:
            output = output_bytes.decode("utf-8")
        except UnicodeDecodeError:
            output = output_bytes.decode("utf-16", errors="ignore")

        # Normalize weird output (nulls, double spaces, blank lines)
        output = output.replace('\x00', '')
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return "\n".join(lines)

    IGNORE_CODES = [9]
    _apt_patch_attempted = False

    def run(self, cmd: list, ignore_codes: list[int] | None = None, debug = True) -> str:
        if not isinstance(cmd, list):
            raise TypeError("Expected a list of command arguments.")

        ignore_codes = self.IGNORE_CODES + (ignore_codes or [])
        if any(part in self.base_cmd for part in ["bash", "-c"]):
            cmd = [' '.join(cmd)]
        real_cmd = self.base_cmd + cmd

        if debug is True: log.debug(f"[WSL.run_command] Running: {real_cmd}")

        spinner_running = True

        def _spinner():
            for c in itertools.cycle(r"\|/-"):
                if not spinner_running:
                    break
                print(f"\r[WSL] Running... {c}", end="", flush=True)
                time.sleep(0.1)

        spinner_thread = threading.Thread(target=_spinner)
        spinner_thread.start()

        try:
            process = subprocess.Popen(
                real_cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            #process.wait()
            output_bytes, _ = process.communicate(timeout=300)
            decoded_output = self._decode_wsl_output(output_bytes)

            if process.returncode == 100 and "apt-get" in " ".join(cmd):
                if any(x in decoded_output.lower() for x in [
                    "could not resolve", "dpkg was interrupted", "unmet dependencies", "unable to fetch"
                ]):
                    log.error("Ubuntu might be corrupted! Uninstalling...")
                    self.delete_distro()
                    raise RuntimeError(f"[WSL] Docker install unrecoverable. Uninstalled distro '{self.distro}'.")
                else:
                    log.warning("apt-get returned 100, but continuing.")

            elif process.returncode != 0 and process.returncode not in ignore_codes:
                raise RuntimeError(f"WSL command failed with return code {process.returncode}")

            #for line in decoded_output.splitlines():
            if decoded_output == "": return ""
            if debug is True: log.debug(f"[WSL.run_command] Decoded output:\n{decoded_output!r}")
            return decoded_output

        except Exception as e:
            log.exception("[WSL.run_command] Failed to execute command.")
            raise

        finally:
            spinner_running = False
            spinner_thread.join()
            print("\r", end="", flush=True)

    INSTALL_CMDS = [
        ["apt-get update"],
        ["apt-get -o Dpkg::Progress-Fancy=1 install -y ca-certificates curl gnupg lsb-release"],
        ["mkdir -p /etc/apt/keyrings"],
        ["curl -fsSL https://download.docker.com/linux/debian/gpg -o /tmp/docker.gpg"],
        ["gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg /tmp/docker.gpg"],
        ["echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] "
         "https://download.docker.com/linux/debian $(lsb_release -cs) stable\" "
         "| tee /etc/apt/sources.list.d/docker.list > /dev/null"],
        ["apt-get update"],
        ["apt-get -o Dpkg::Progress-Fancy=1 install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin"],
    ]

    def looper(self, cmd_list: list, ignore_codes: list = None):
        for i, cmd in enumerate(cmd_list):
            try:
                log.info(f"[WSL.looper] Running command {i+1}/{len(cmd_list)}...")
                self.run(cmd, ignore_codes)
            except Exception as e:
                log.error(f"[WSL.looper] Command failed: {cmd}")
                raise RuntimeError(e)

    def _is_root(self) -> bool:
        """
        Returns True if running as root inside WSL.
        """
        try:
            # run(["id", "-u"]) executes in WSL and returns "0" if root
            output = self.run(["id", "-u"], ignore_codes=[], interactive=False).strip()
            return output == "0"
        except Exception:
            return False

    PASSWORDLESS_SUDO_CMDS = [
        ["bash", "-c", "echo '[user]\\ndefault=root' | sudo tee /etc/wsl.conf"],
        ["bash", "-c", "echo 'root ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/root"],
        ["bash", "-c", "sudo chmod 440 /etc/sudoers.d/root"],
    ]

    def passwordless_sudo(self):
        """
        Ensure that WSL’s default user is root and grant root NOPASSWD sudo.
        Steps:
          1. If we’re already root (id -u == 0), nothing to do.
          2. If not root, try each command non‐interactively.
             If sudo requires a password, self.run(...) will raise,
             and we tell the user to do it manually.

        All defined variables:
            is_root: bool
            cmd: list[str]
        """
        # 1. Check for root
        if self._is_root():
            log.info("[WSL.passwordless_sudo] Already running as root—skipping.")
            return

        # 2. Try to run each command without interactive stdin
        for cmd in self.PASSWORDLESS_SUDO_CMDS:
            try:
                log.info(f"[WSL.passwordless_sudo] Attempting: {' '.join(cmd)}")
                self.run(cmd, ignore_codes=[], interactive=False)
            except RuntimeError as e:
                log.error("[WSL.passwordless_sudo] Sudo needs a password or failed.")
                # Bail out—tell the user exactly what to run by hand.
                raise RuntimeError(
                    "Unable to grant passwordless sudo. "
                    "Please run these inside WSL as root:\n"
                    f"    {cmd}"
                ) from e

        # If we made it here, all commands succeeded
        os.environ["passwordless_sudo"] = "True"
        log.success("[WSL.passwordless_sudo] Passwordless sudo configured.")
        return

if __name__ == "__main__":
    path = Path("C:\\Users\\cblac\\PycharmProjects\\mileslib2\\foobar\\Dockerfile.foobar")
    log.info("foobar")
    Docker.get_instance()
    # DockerImage.get_instance(path, "foobar")
    # user = AzureUserLogin("foobar")