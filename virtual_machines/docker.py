import itertools
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from loguru import logger as log


class DockerImage:
    instances = {}

    @staticmethod
    def to_wsl_path(pathlib_path: Path | str) -> str:
        if isinstance(pathlib_path, Path):
            pathlib_path = str(pathlib_path)
        return pathlib_path.replace(":", "").replace("\\", "/").replace("C", "/mnt/c")

    def __init__(self, dockerfile: Path, rebuild: bool = True):
        self.uuid = uuid.uuid4()
        self.docker = Docker.get_instance()
        self.dockerfile_path = dockerfile
        self.dockerfile_str = self.to_wsl_path(self.dockerfile_path)
        self.dockerfile_parent_path = self.to_wsl_path(self.dockerfile_path.parent.resolve())
        self.image_name = self.dockerfile_path.name.replace("Dockerfile.", "")
        self.base_cmd = ["run", "-i", "--rm", self.image_name]
        found_image = self.find_image()
        if found_image is False or rebuild is True: self.build()
        log.success(f"Docker Image Initialized: {self.uuid}, {self.image_name}")

    def find_image(self) -> bool:
        cmd = ["images", "--format", "{{.Repository}}"]
        log.info(f"Attempting to find image for {self.image_name}")
        result = self.docker.run(cmd, ignore_codes=[1])
        if self.image_name not in result:
            return False
        return True

    def build(self):
        cmd = ["build", "-f", str(self.dockerfile_str), "-t", self.image_name, str(self.dockerfile_parent_path)]
        try:
            log.debug(self.docker.run(cmd))
        except Exception as e:
            log.exception(f"[Docker.build] Exception: {e}")
            raise

    @classmethod
    def get_instance(cls, dockerfile: Path, rebuild: bool = True):
        log.debug(cls.instances)
        if not dockerfile.exists():
            raise FileNotFoundError(f"Dockerfile not found at: {dockerfile}")

        dockerfile_str = str(dockerfile.resolve())
        image_name = dockerfile_str.replace("Docker.", "")

        if image_name in cls.instances:
            return cls.instances[image_name]
        instance = cls(dockerfile, rebuild=rebuild)
        cls.instances[image_name] = instance
        return instance

    def run(self, cmd: list = None):
        real_cmd = self.base_cmd + cmd
        if not cmd: real_cmd = self.base_cmd
        result = self.docker.run(real_cmd)
        return result

class Docker:
    instance = None

    def __init__(self):
        self.uuid = uuid.uuid4()
        self.wsli = WSL.get_instance()
        # self.wsli_user = WSL.get_instance(root=False)
        self.base_cmd = ["docker"]
        self.check_docker_ready()
        log.success(f"Docker Instance Initialized: {self.uuid}")

    @classmethod
    def get_instance(cls):
        if cls.instance is None:
            cls.instance = cls()
        return cls.instance

    def run(self, cmd: list, ignore_codes: list = None):
        if not isinstance(cmd, list): raise TypeError
        if ignore_codes is not None:
            if not isinstance(ignore_codes, list): raise TypeError
        real_cmd = self.base_cmd + cmd
        output = self.wsli.run(real_cmd, ignore_codes=ignore_codes)
        return output

    INSTALL_DOCKER_COMMANDS = [
        ["curl -fsSL https://get.docker.com -o get-docker.sh"],
        ["sudo sh get-docker.sh"],
        ["sudo usermod -aG docker mileslib"],
        ["docker --version"],
        ["docker compose version"]
    ]
    DOCKER_BOOT_CMDS = [
        ["grep -q '\\-WSL2' /proc/version || exit 0"],
        ['service docker status 2>&1 | grep -q "is not running"'],
        ['sudo service docker start'],
        ['docker info'],
        ['docker run hello-world']
    ]

    def check_docker_ready(self):
        check_cmd = self.base_cmd + ["version", "--format", "{{.Server.Version}}"]
        output = self.wsli.run(check_cmd, ignore_codes=[127, 1], debug=True)

        if "command not found" in output.lower():
            log.warning("Docker not found. Installing...")
            try:
                output = self.wsli.looper(self.INSTALL_DOCKER_COMMANDS, ignore_codes=[1])
                log.debug(output)
            except Exception as e:
                raise RuntimeError(f"Docker install failed: {e}")

        self.wsli.looper(self.DOCKER_BOOT_CMDS)

    #def uninstall(self):
    #    try:
    #        self.wsli.looper(self.DEBIAN_DOCKER_UNINSTALL_CMDS)
    #    except Exception:
    #        raise RuntimeError("Error uninstalling Docker!")
    #    sys.exit()


class WSL:
    instances = {}

    def __init__(self, distro: str = "Debian", root: bool = True):
        self.path = r"C:\Windows\System32\wsl.exe"
        self.uuid = uuid.uuid4()
        self.base_cmd = [self.path]
        log.debug("\n" + self.run(["--version"], debug=False))
        self.distro = distro
        self.check_distro(distro)
        # reinit base_cmd
        if root is True:
            self.base_cmd = [
                self.path,  # "C:\\Windows\\System32\\wsl.exe"
                "-d", self.distro,  # "-d Debian"
                "-u", "root",  # <— force root every time
                "--", "bash",  # "--exec bash"
                "-ic"  # "-c" so we can pass a single command string
            ]
            log.debug(self.run(['adduser --disabled-password --gecos "" mileslib'], ignore_codes=[1], debug=False))
        else:
            self.base_cmd = [
                self.path,  # "C:\\Windows\\System32\\wsl.exe"
                "-d", self.distro,  # "-d Debian"
                "-u", "mileslib",  # <— force root every time
                "--", "bash",  # "--exec bash"
                "-ic"  # "-c" so we can pass a single command string
            ]
        log.success(f"WSL Instance Initialized: {self.uuid}, {self.distro}, root: {root}")

    @classmethod
    def get_instance(cls, root: bool = True):
        if shutil.which("wsl") is None:
            log.warning("WSL is not installed or not in PATH! Attempting install...")
            cls.install_wsl()
            if shutil.which("wsl") is None:
                raise RuntimeError("WSL installation failed or not available on PATH.")
        else:
            log.success("WSL is installed and available")

        root_str = str(root)
        if root_str not in cls.instances:
            cls.instances[root_str] = cls(root=root)
        return cls.instances[root_str]

    @staticmethod
    def install_wsl():
        try:
            subprocess.run(["wsl", "--install"], check=True)
            log.success("WSL install initiated.")
        except Exception as e:
            log.error("WSL installation failed.")
            raise RuntimeError("WSL installation failed.") from e

    @property
    def dir(self):
        return Path(r"\\wsl$\Debian\home")

    def check_distro(self, distro: str) -> str:
        list_cmd = ["--list", "--quiet"]
        install_cmd = ["cmd.exe", "/c", "start", "cmd.exe", "/k", f"wsl --install -d {distro}"]

        def check():
            try:
                listed_distros = self.run(list_cmd)
                if distro in listed_distros:
                    log.success(f"✅ Distro '{distro}' found.")
                else:
                    raise RuntimeError(f"❌ Distro '{distro}' not found.")
            except subprocess.CalledProcessError as er:
                log.error("WSL list command failed.")
                raise RuntimeError("WSL list command failed.") from er

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
                        log.success(f"\n✅ Distro '{self.distro}' is now installed.")
                        break
                except Exception:
                    pass

        if not isinstance(distro, str):
            raise TypeError("distro must be a string")

        try:
            check()
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
            log.success(f"Distro '{self.distro}' has been deleted.")
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

    def run(self, cmd: list, ignore_codes: list[int] | None = None, debug=True) -> str | None:
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

        process = None

        try:
            process = subprocess.Popen(
                real_cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            # process.wait()
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

            if process.returncode == 1:
                log.warning(decoded_output)

            elif process.returncode != 0 and process.returncode not in ignore_codes:
                raise

            # for line in decoded_output.splitlines():
            if decoded_output == "": return ""
            if debug is True: log.debug(f"[WSL.run_command] Decoded output:\n{decoded_output!r}")
            return decoded_output

        except Exception:
            log.exception("[WSL.run_command] Failed to execute command.")
            log.error(process.stderr)
            raise

        finally:
            spinner_running = False
            spinner_thread.join()
            print("\r", end="", flush=True)

    def looper(self, cmd_list: list, ignore_codes: list = None):
        looper_output = {}
        for i, cmd in enumerate(cmd_list):
            try:
                log.debug(f"[WSL.looper] Running command {i + 1}/{len(cmd_list)}...")
                output = self.run(cmd, ignore_codes)
                cmd_str = str(cmd)
                looper_output[cmd_str] = output
            except Exception as e:
                log.error(f"[WSL.looper] Command failed: {cmd}")
                raise RuntimeError(e)
        log.debug(looper_output)
        return looper_output


if __name__ == "__main__":
    path = Path.cwd() / "Dockerfile.foobar"
    inst = DockerImage.get_instance(path)
