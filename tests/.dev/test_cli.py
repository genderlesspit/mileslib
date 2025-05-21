# core.py
import os
import click
import subprocess
import shutil
from pathlib import Path
from mileslib import StaticMethods as sm

class CLI:
    """
    Command-line interface handler for MilesLib commands.

    Methods:
        launch(): Starts the CLI command group.
    """
    def __init__(self):
        """
        Initialize the CLI with command registration.
        """
        self.cli = click.Group(
            invoke_without_command=True,
            context_settings={"help_option_names": ["--help", "-h"]}
        )
        self._register_commands()

    def launch(self):
        """
        Launch the CLI group. Entry point for CLI execution.
        """
        self.cli()

    def _register_commands(self):
        """
        Register all subcommands to the CLI group.
        """
        self.cli.add_command(self.CMDs.run_setup)
        self.cli.add_command(self.CMDs.run_init)

    class CMDs:
        #RUN SETUP
        @staticmethod
        @click.command(name="setup")
        @click.option(
            "--root",
            type=click.Path(file_okay=False, dir_okay=True),
            default=".",
            show_default=True,
            help="Root directory to initialize MilesLib in.",
        )
        def run_setup(root):
            """
            Set up the MilesLib root directory and configuration file.

            Args:
                root (str): Path to the desired root directory.

            Side Effects:
                Creates `_config/mileslib_config.toml` and sets Directory.absolute_path.

            Raises:
                click.Abort: If setup fails due to a validation or filesystem error.
            """
            try:
                root_path = Path(root).resolve()
                Directory(root_path)
                click.echo(f"[setup] MilesLib initialized at: {root_path}")
            except Exception as e:
                click.echo(f"[error] Failed to initialize MilesLib: {e}")
                raise click.Abort()

        #RUN INITIALIZATION
        @staticmethod
        @click.command(name="init")
        @click.argument("project_name")
        def run_init(project_name):
            """
            Initialize a new MilesLib-compatible project under the current root.

            Args:
                project_name (str): Name of the new project directory to create.

            Raises:
                RuntimeError: If MilesLib root is not initialized.
            """
            try:
                CLI.Methods.init_project(project_name)
            except RuntimeError as e:
                click.echo(str(e))
                raise click.Abort()

    class Methods:
        @staticmethod
        def init_project(project_name: str):
            """
            Create a new project folder with default structure and Django scaffold.

            Args:
                project_name (str): Name of the project to be created.

            Side Effects:
                - Creates folders: _config, _tests, _logs, .tmp
                - Writes a default settings.toml config file
                - Runs `django-admin startproject`

            Raises:
                RuntimeError: If root is not initialized.
                subprocess.CalledProcessError: If Django project creation fails.
            """
            Directory.is_initialized()
            root = Directory.absolute_path / project_name
            cfg = root / "_config"
            tests = root / "_tests"
            logs = root / "_logs"
            tmp = root / ".tmp"

            try:
                click.echo(f"[init] Creating directories for '{project_name}'...")
                for d in [root, cfg, tests, logs, tmp]:
                    sm.validate_directory(d)

                click.echo("[init] Writing default configuration...")
                sm.cfg_write(
                    pdir=root,
                    file_name="settings.toml",
                    data={
                        "valid": True,
                        "project": project_name,
                        "env": {"active": "default"},
                        "paths": {
                            "config": str(cfg),
                            "logs": str(logs),
                            "tmp": str(tmp)
                        }
                    },
                    overwrite=False,
                    replace_existing=False
                )

                click.echo("[init] Initializing Django project...")
                subprocess.run(
                    ["python", "-m", "django", "startproject", project_name, str(root)],
                    check=True
                )

            except Exception as e:
                click.echo(f"[error] {project_name} initialization failed!: {e}")
                if root.exists():
                    shutil.rmtree(root)
                click.echo("[abort] Setup aborted.")
                exit(1)
import pytest
import shutil
import subprocess
from pathlib import Path
from click.testing import CliRunner

@pytest.fixture
def clean_dir(tmp_path):
    yield tmp_path
    if tmp_path.exists():
        shutil.rmtree(tmp_path)

def test_directory_is_initialized_after_setup(monkeypatch, clean_dir):
    monkeypatch.setattr(sm, "validate_directory", lambda p: Path(p))
    monkeypatch.setattr(sm, "validate_file", lambda p: Path(p))
    monkeypatch.setattr(Path, "exists", lambda self: False)
    monkeypatch.setattr(sm, "cfg_write", lambda **kwargs: None)

    Directory(clean_dir)

    assert Directory.is_initialized() is True


def test_cli_setup_creates_root(monkeypatch, clean_dir):
    """Test CLI 'setup' command initializes Directory."""
    runner = CliRunner()
    Directory.absolute_path = None
    Directory.setup_complete = False

    print(f"\n[DEBUG] Using clean_dir: {clean_dir}")

    monkeypatch.setattr(sm, "validate_directory", lambda p: Path(p))
    monkeypatch.setattr(sm, "validate_file", lambda p: Path(p))
    monkeypatch.setattr(sm, "cfg_write", lambda **kwargs: print(f"[DEBUG] cfg_write called with: {kwargs}"))

    cli = CLI().cli
    result = runner.invoke(cli, ["setup", "--root", str(clean_dir)])

    print(f"[DEBUG] CLI Output:\n{result.output}")
    print(f"[DEBUG] Exit Code: {result.exit_code}")
    print(f"[DEBUG] Directory.absolute_path: {Directory.absolute_path}")
    print(f"[DEBUG] Directory.setup_complete: {Directory.setup_complete}")

    assert result.exit_code == 0
    assert "[setup] MilesLib initialized at" in result.output
    assert Directory.absolute_path == clean_dir
    assert Directory.setup_complete is True

def test_cli_init_project(monkeypatch, clean_dir):
    """Test CLI 'init' command scaffolds project when root is set."""
    runner = CliRunner()
    Directory.absolute_path = clean_dir  # manually simulate setup

    monkeypatch.setattr(sm, "validate_directory", lambda p: Path(p))
    monkeypatch.setattr(sm, "cfg_write", lambda **kwargs: None)
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: None)

    cli = CLI().cli
    result = runner.invoke(cli, ["init", "demo_proj"])

    assert result.exit_code == 0
    assert "[init] Creating directories for 'demo_proj'" in result.output
    assert "[init] Writing default configuration..." in result.output
    assert "[init] Initializing Django project..." in result.output


def test_cli_init_without_setup(monkeypatch):
    """Test that 'init' fails if Directory is not initialized."""
    runner = CliRunner()
    Directory.absolute_path = None  # simulate missing setup
    Directory.setup_complete = False

    print("\n[DEBUG] Simulating uninitialized Directory")
    cli = CLI().cli
    result = runner.invoke(cli, ["init", "failing_proj"])

    print(f"[DEBUG] CLI Output:\n{result.output}")
    print(f"[DEBUG] Exit Code: {result.exit_code}")
    print(f"[DEBUG] Directory.absolute_path: {Directory.absolute_path}")
    print(f"[DEBUG] Directory.setup_complete: {Directory.setup_complete}")

    assert result.exit_code != 0
    assert "MilesLib root not initialized" in result.output


class Directory:
    """
    Handles root directory validation, configuration setup, and global project state.

    Attributes:
        setup_complete (bool): Indicates whether initialization has completed.
        absolute_path (Path): The validated root directory of the MilesLib project.
    """
    setup_complete = False
    absolute_path = None

    def __init__(self, root: Path = None):
        """
        Initialize the Directory object and set up the core configuration structure.

        Args:
            root (Path, optional): Custom root path. Defaults to current working directory.

        Raises:
            ValueError: If the directory or config file cannot be created or validated.
        """
        self.root = sm.validate_directory((root or os.getcwd()).resolve())
        Directory.absolute_path = self.root
        self.config_name = "mileslib_config.toml"
        self.config_dir = sm.validate_directory(self.root / "_config")
        self.config_path = sm.validate_file(self.config_dir / self.config_name )
        if not self.config_path.exists():
            sm.cfg_write(
                pdir=self.root,
                file_name=self.config_name,
                data={
                    "valid": True,
                    "absolute_root": f"{self.root}",
                    "active_projects": {
                    }
                },
                overwrite=False,
                replace_existing=False
            )
        Directory.setup_complete = True

    @staticmethod
    def is_initialized() -> bool:
        """
        Check if the MilesLib root directory has been initialized.

        Returns:
            bool: True if initialized.

        Raises:
            RuntimeError: If the root has not been set up yet.
        """
        if Directory.absolute_path is None:
            raise RuntimeError(
                "MilesLib root not initialized. Run `mileslib setup` to initialize the project root."
            )
        return True

#IS_INITIALIZED = Directory.is_initialized()
ABSOLUTE_PATH = Directory.absolute_path
DIRECTORY_USAGE = """
MilesLib Directory Constants
----------------------------

• IS_INITIALIZED
    → bool: True if MilesLib root has been initialized via Directory().
    → Raises RuntimeError if accessed before initialization.
    → Alias: Directory.is_initialized()

• ABSOLUTE_PATH
    → Path: The absolute root directory of the current MilesLib project.
    → Set automatically during Directory() instantiation.
    → Alias: Directory.absolute_path
"""

import os
import shutil
import pytest
from pathlib import Path
from mileslib import StaticMethods as sm

@pytest.fixture
def clean_dir(tmp_path):
    """Temporary clean directory to simulate project root."""
    yield tmp_path
    if tmp_path.exists():
        shutil.rmtree(tmp_path)

def test_directory_initializes_config(monkeypatch, clean_dir):
    """Test that Directory sets up root and creates the config if missing."""
    captured = {}

    monkeypatch.setattr(sm, "validate_directory", lambda p: Path(p))
    monkeypatch.setattr(sm, "validate_file", lambda p: Path(p))
    monkeypatch.setattr(Path, "exists", lambda self: False)
    monkeypatch.setattr(sm, "cfg_write", lambda **kwargs: captured.update(kwargs))

    Directory(clean_dir)

    assert Directory.setup_complete is True
    assert Directory.absolute_path == clean_dir
    assert captured["pdir"] == clean_dir
    assert captured["file_name"] == "mileslib_config.toml"
    assert "data" in captured
    assert captured["data"]["valid"] is True

def test_directory_skips_cfg_write_if_exists(monkeypatch, clean_dir):
    """Ensure cfg_write is not called if config file exists."""

    # Save original before patching
    original_exists = Path.exists

    monkeypatch.setattr(sm, "validate_directory", lambda p: Path(p))
    monkeypatch.setattr(sm, "validate_file", lambda p: Path(p))

    expected = Path(clean_dir / "_config" / "mileslib_config.toml")

    def fake_exists(self):
        if self == expected:
            return True
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    called = {"written": False}

    def fake_write(**kwargs):
        called["written"] = True

    monkeypatch.setattr(sm, "cfg_write", fake_write)

    Directory(clean_dir)

    assert called["written"] is False

def test_is_initialized_true(monkeypatch, clean_dir):
    """Check that is_initialized returns True if root is set."""
    Directory.absolute_path = clean_dir
    assert Directory.is_initialized() is True


def test_is_initialized_false_raises():
    """Check that is_initialized raises RuntimeError if root not set."""
    Directory.absolute_path = None
    with pytest.raises(RuntimeError, match="MilesLib root not initialized"):
        Directory.is_initialized()