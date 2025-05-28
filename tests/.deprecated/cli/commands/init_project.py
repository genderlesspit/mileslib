import sys
import click
from pathlib import Path
import subprocess
import shutil
from mileslib_core import StaticMethods as sm

def init(project_name: str):
    PROJECT_NAME = project_name
    pdir = Path.cwd() / project_name
    PROJECT_ROOT = Path(pdir)
    CONFIG_DIR = PROJECT_ROOT / "_config"
    TESTS_DIR = PROJECT_ROOT / "_tests"
    LOG_DIR = PROJECT_ROOT / "_logs"
    TMP_DIR = PROJECT_ROOT / ".tmp"
    DIRS = [PROJECT_ROOT, CONFIG_DIR, TESTS_DIR, LOG_DIR, TMP_DIR]

    def dir_setup(project_name):
        click.echo(f"[init] Creating directories for '{project_name}'...")
        for dir in DIRS:
            sm.validate_directory(dir)

    def setup_config(project_name):
        click.echo("[init] Writing default configuration...")
        sm.cfg_write(
            pdir=PROJECT_ROOT,
            file_name="settings.toml",
            data={
                "valid": True,
                "project": project_name,
                "env": {"active": "default"},
                "paths": {
                    "config": str(CONFIG_DIR),
                    "logs": str(LOG_DIR),
                    "tmp": str(TMP_DIR)
                }
            },
            overwrite=False,
            replace_existing=False
        )

    def django_setup(project_name):
        print("[init] Initializing Django project")
        subprocess.run(
            ["python", "-m", "django", "startproject", project_name],
            check=True
        )

    SETUP_METHODS = [dir_setup, setup_config, django_setup]

    def abort():
        click.echo(f"[abort] Cleaning up {PROJECT_ROOT}")
        if PROJECT_ROOT.exists():
            shutil.rmtree(PROJECT_ROOT)
        click.echo("[abort] Setup aborted.")
        exit(1)

    for setup_fn in SETUP_METHODS:
        try:
            setup_fn(project_name)
        except Exception as e:
            click.echo(f"[error] {PROJECT_NAME} initialization failed!: {e}")
            abort()

@click.command()
@click.argument("project_name")
def run(project_name: str):
    """Scaffolds a new MilesLib-compatible project by name."""
    init(project_name=project_name)

import pytest
import shutil
from pathlib import Path
from click.testing import CliRunner

@pytest.fixture
def clean_test_dir(tmp_path):
    """Creates a clean test project path."""
    test_dir = tmp_path / "test_project"
    yield test_dir
    if test_dir.exists():
        shutil.rmtree(test_dir)

def test_init_creates_directories(monkeypatch, clean_test_dir):
    runner = CliRunner()

    # Mock file system + subprocess
    monkeypatch.setattr("cli.commands.init_project.sm.validate_directory", lambda p: p.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr("cli.commands.init_project.sm.cfg_write", lambda **kwargs: None)
    monkeypatch.setattr("cli.commands.init_project.subprocess.run", lambda *a, **kw: None)

    result = runner.invoke(run, [clean_test_dir.name], catch_exceptions=False)

    assert result.exit_code == 0, f"CLI failed:\n{result.output}"


def test_init_writes_config(monkeypatch, clean_test_dir):
    written_config = {}

    def fake_cfg_write(pdir, file_name, data, overwrite, replace_existing):
        written_config.update(data)

    monkeypatch.setattr("cli.commands.init_project.sm.validate_directory", lambda p: p.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr("cli.commands.init_project.sm.cfg_write", fake_cfg_write)
    monkeypatch.setattr("cli.commands.init_project.subprocess.run", lambda *a, **kw: None)

    runner = CliRunner()
    runner.invoke(run, [clean_test_dir.name], catch_exceptions=False)

    assert "valid" in written_config
    assert written_config["project"] == clean_test_dir.name
    assert "paths" in written_config


def test_init_aborts_on_exception(monkeypatch, clean_test_dir):
    monkeypatch.setattr("cli.commands.init_project.sm.validate_directory", lambda p: (_ for _ in ()).throw(Exception("fail dir")))
    monkeypatch.setattr("cli.commands.init_project.shutil.rmtree", lambda path: None)

    runner = CliRunner()
    result = runner.invoke(run, [clean_test_dir.name], catch_exceptions=False)

    assert result.exit_code == 1
    assert "Setup aborted" in result.output

import subprocess
import pytest
from pathlib import Path

@pytest.fixture
def dummy_project_path(tmp_path):
    return tmp_path / "testproj"