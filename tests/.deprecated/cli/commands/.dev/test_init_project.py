import click
from tests.mileslib_core import MilesLib
from tests.mileslib_core import sm
import subprocess


def init(ctx, project_name: str):
    miles = ctx.obj["miles"]
    PROJECT_NAME = project_name
    pdir = Path.cwd() / project_name
    PROJECT_ROOT = Path(pdir)
    CONFIG_DIR = PROJECT_ROOT / "_config"
    TESTS_DIR = PROJECT_ROOT / "_tests"
    LOG_DIR = PROJECT_ROOT / "_logs"
    TMP_DIR = PROJECT_ROOT / ".tmp"
    DIRS = [PROJECT_ROOT, CONFIG_DIR, TESTS_DIR, LOG_DIR, TMP_DIR]

    def dir_setup():
        click.echo(f"[init] Creating directories for '{project_name}'...")
        for dir in DIRS:
            sm.validate_directory(dir)
        raise NotImplementedError

    def setup_config():
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
            ["python", "-m", "django", "startproject", project_name, str(PROJECT_ROOT)],
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
            setup_fn()
        except Exception as e:
            click.echo(f"[error] {PROJECT_NAME} initialization failed!: {e}")
            abort()

@click.command()
@click.argument("project_name")
@click.pass_context
def run(ctx, project_name: str):
    """Scaffolds a new MilesLib-compatible project by name."""
    miles: MilesLib = ctx.obj["miles"]
    init(ctx, project_name=project_name)

import pytest
import shutil
import tempfile
from click.testing import CliRunner
from pathlib import Path
from types import SimpleNamespace

@pytest.fixture
def temp_miles():
    temp_dir = Path(tempfile.mkdtemp())

    def fake_logger_info(msg, extra=None):
        print(f"[LOG] {msg} | Extra: {extra}")

    miles = SimpleNamespace(
        pdir=temp_dir,
        logger=SimpleNamespace(info=fake_logger_info)
    )

    ctx = {"miles": miles}
    yield ctx, temp_dir

    shutil.rmtree(temp_dir)

def test_init_project_success(temp_miles):
    ctx, temp_dir = temp_miles
    runner = CliRunner()
    project_name = "testproject"

    result = runner.invoke(init, [project_name], obj=ctx)

    assert result.exit_code == 0
    root = temp_dir / project_name
    assert (root / "_config").exists()
    assert (root / "_tests").exists()
    assert (root / "_logs").exists()
    assert (root / ".tmp").exists()
    assert (root / project_name).exists()  # Django project root

def test_init_aborts_on_failure(monkeypatch, temp_miles):
    ctx, temp_dir = temp_miles
    project_name = "failproject"
    root = temp_dir / project_name

    # Force failure by mocking one setup function to raise
    def fake_dir_setup():
        raise Exception("Failing on purpose")

    monkeypatch.setattr(init, "sm", ctx["miles"].logger)  # For logging fallback
    monkeypatch.setattr(init, "init", lambda ctx, project_name: fake_dir_setup())

    runner = CliRunner()
    result = runner.invoke(run, [project_name], obj=ctx)

    assert result.exit_code != 0
    assert not root.exists()
