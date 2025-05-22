import shutil
from unittest import mock
import pytest
import importlib.util
import requests
import toml
from typing import Any, List, Union, Mapping, Sequence, Callable, Tuple, Type, Optional
from types import ModuleType
import json
import importlib.util
import subprocess
import time
from pathlib import Path
import sys
import os
import tempfile
import zipfile
from datetime import datetime
from dynaconf import Dynaconf
import click
from mileslib import StaticMethods as sm

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
        try:
            self.config_path = sm.validate_file(self.config_dir / self.config_name )
        except FileNotFoundError:
            sm.cfg_write(
                pdir=self.root,
                file_name=self.config_name,
                data={
                    "valid": True,
                    "absolute_root": f"{self.root}",
                },
                section="mileslib",
                overwrite=False,
                replace_existing=False
            )
        except IsADirectoryError:
            raise RuntimeError("Config file is actually a directory...? How did this happen?")

        Directory.setup_complete = True

    @staticmethod
    def validate():
        """
        Ensure the MilesLib project root is properly initialized and accessible.

        This method follows a multi-step validation flow:
          1. If `Directory.absolute_path` is already set, return it immediately.
          2. Otherwise, attempt to load the project root from the local config file at `_config/mileslib_config.toml`.
          3. If the config is missing or malformed, automatically invoke `mileslib setup` via subprocess.
          4. After setup, retry loading the configuration to finalize initialization.

        Returns:
            Path: The absolute path of the MilesLib project root.

        Raises:
            RuntimeError: If initialization fails due to missing config, setup failure, or unreadable config state.
        """
        def _load_from_config() -> Path:
            """
            Restore Directory.absolute_path from the on-disk config file.
            """
            print("[validate] Attempting to load config from disk...")
            root = Path(os.getcwd()).resolve()
            config_path = root / "_config" / "mileslib_config.toml"
            print(f"[validate] Looking for config at: {config_path}")

            if not config_path.exists():
                print("[validate] Config file does not exist.")
                raise RuntimeError("Could not initialize from config. Run `mileslib setup` first.")

            print("[debug] Using pdir for cfg_get:", root)
            absolute_root_str = sm.cfg_get("absolute_root", pdir=root, section="mileslib")
            print("[debug] absolute_root from config:", absolute_root_str)

            if absolute_root_str is None:
                raise RuntimeError("Config file is missing 'absolute_root'. Run `mileslib setup` again.")

            absolute_path = Path(absolute_root_str)

            if not absolute_path.exists():
                print("[validate] Config absolute_root path does not exist on filesystem.")
                raise RuntimeError("Could not initialize from config. Run `mileslib setup` first.")

            Directory.absolute_path = absolute_path
            Directory.setup_complete = True
            print(f"[validate] Directory initialized from config: {absolute_path}")
            print(f"Acknowledged Directory class setup: {Directory.setup_complete}")
            print(f"Acknowledged Directory class absolute path: {Directory.absolute_path}")

            return absolute_path

        def _setup():
            print("[validate] Running setup subprocess...")
            result = subprocess.run(
                ["python", "-m", "mileslib", "setup"],
                capture_output=True,
                text=True
            )

            print("[stdout]", result.stdout)
            print("[stderr]", result.stderr)
            print("[exit code]", result.returncode)

            if result.returncode != 0:
                print("[error] MilesLib setup failed.")
                raise RuntimeError("Critical error with core MilesLib setup logic. Please report on github.")
            else:
                print("[success] MilesLib root initialized.")

        if Directory.setup_complete is True and Directory.absolute_path.exists():
            print(f"[validate] Already marked complete: {Directory.absolute_path}")
            return Directory.absolute_path

        print(f"[validate] Could not initialize. Attempting to find config...")
        try:
            return _load_from_config()
        except RuntimeError as e:
            print(f"[validate] Config load failed: {e}")
            print("[validate] Config not found or invalid. Attempting setup...")
            _setup()
            return _load_from_config()

#IS_INITIALIZED = Directory.is_initialized()
DIRECTORY_USAGE="""
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
        print(f"[debug] CLI args: {sys.argv}")
        self.Project.dispatch_or_fallback(self.cli)  # <- new dynamic entrypoint

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

            #Validate Directory
            click.echo("[debug] Validating Directory ...")
            try:
                root = Directory.validate() / project_name
                click.echo(f"[debug] {root} successfully identified as project root.")
            except Exception as e:
                click.echo(f"[validate error]: {e}")
                raise click.Abort

            proj_root = sm.validate_directory(root)
            cfg = root / "_config"
            tests = root / "_tests"
            logs = root / "_logs"
            tmp = root / ".tmp"
            django_name = f"{project_name}_core"

            def init_django():
                click.echo("[init] Initializing Django project...")
                subprocess.run(
                    ["python", "-m", "django", "startproject", django_name, proj_root],
                    check=True
                )

            def init_directories():
                click.echo(f"[init] Creating directories for '{project_name}'...")
                for d in [root, cfg, tests, logs, tmp]:
                    sm.validate_directory(d)

            def init_config():
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

            def acknowledge_project():
                click.echo("[init] Acknowledging project globally...")
                sm.cfg_write(
                    pdir=Directory.absolute_path,
                    file_name="mileslib_config.toml",
                    data={
                        f"{project_name}": proj_root
                    },
                    section="active_projects"
                )

            try:
                init_django()
                init_directories()
                init_config()
                acknowledge_project()

            except Exception as e:
                click.echo(f"[error] {project_name} initialization failed!: {e}")
                if root.exists():
                    shutil.rmtree(root)
                click.echo("[abort] Setup aborted.")
                exit(1)

    class Project:
        @staticmethod
        def dispatch_or_fallback(main_cli):
            args = sys.argv[1:]
            if not args or args[0].startswith("-"):
                return main_cli()  # no project name provided, run top-level CLI

            project_name = args[0]
            try:
                root = Directory.validate()
                config = sm.cfg_get("active_projects", pdir=root)
                if project_name not in config:
                    click.echo(f"[error] Unknown project: '{project_name}'")
                    return main_cli()

                project_path = Path(config[project_name])
                ctx = {"project": project_name, "project_path": project_path}

                # Dispatch to the project CLI with remaining args
                CLI.Project.project_cli().main(args=args[1:], obj=ctx, standalone_mode=False)

            except Exception as e:
                click.echo(f"[critical] Could not dispatch project command: {e}")
                return main_cli()

        @staticmethod
        def project_cli():
            @click.group()
            @click.pass_context
            def cli(ctx):
                """Project-scoped commands"""
                pass

            # Register all subcommands
            cli.add_command(CLI.Project.CMDs.run_diagnostic)
            # Future commands here...
            return cli

        class CMDs:
            @staticmethod
            @click.command(name="diagnostic")
            @click.pass_context
            def run_diagnostic(ctx):
                """
                Run diagnostic checks on this project.

                Args:
                    ctx (click.Context): CLI context with project metadata.
                """
                try:
                    project = ctx.obj["project"]
                    path = ctx.obj["project_path"]
                    CLI.Project.Methods.run_diagnostic_logic(project, path)
                except Exception as e:
                    click.echo(f"[error] Diagnostic failed: {e}")
                    raise click.Abort()

        class Methods:
            @staticmethod
            def run_diagnostic_logic(project: str, path: Path):
                """
                Core diagnostic logic.

                Args:
                    project (str): Name of the project.
                    path (Path): Path to the project directory.
                """
                click.echo(f"[diagnostic] Running checks for: {project} at {path}")
                if not (path / "_config").exists():
                    raise RuntimeError("Missing _config directory.")
                click.echo("[diagnostic] Configuration looks valid.")

