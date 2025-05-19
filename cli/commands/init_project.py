import click
from mileslib import MilesLib
import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock

def init(project_name: str, stack: str, pdir, logger):
    logger.info("Scaffolding project", extra={"project_name": project_name, "stack": stack})
    # Example scaffold behavior
    click.echo(f"Scaffolding project '{project_name}' using stack '{stack}' in {pdir}")
    # Add your actual scaffolding logic here

@click.command()
@click.argument("project_name")
@click.option(
    "--stack",
    type=click.Choice(["django_app", "fastapi_app", "azure-hybrid", "all"], case_sensitive=False),
    default="all",
    required=True,
    help="Choose the stack to scaffold.",
)
@click.pass_context
def run(ctx, project_name: str, stack: str):
    """Scaffolder for various web-development stacks."""
    miles = ctx.obj["miles"]
    log = miles.logger
    log.info("CLI Init called", extra={"project_name": project_name, "stack": stack})
    init(project_name=project_name, stack=stack, pdir=miles.pdir, logger=miles.logger)

@pytest.fixture
def fake_miles_context(tmp_path):
    logger = MagicMock()
    miles = MagicMock()
    miles.pdir = tmp_path
    miles.logger = logger
    return {"miles": miles}, logger

def test_run_fastapi_stack(fake_miles_context):
    ctx_obj, logger = fake_miles_context
    runner = CliRunner()
    result = runner.invoke(run, ["myfastapi", "--stack", "fastapi_app"], obj=ctx_obj)

    assert result.exit_code == 0
    assert "Scaffolding project 'myfastapi' using stack 'fastapi_app'" in result.output
    logger.info.assert_any_call("CLI Init called", extra={"project_name": "myfastapi", "stack": "fastapi_app"})
    logger.info.assert_any_call("Scaffolding project", extra={"project_name": "myfastapi", "stack": "fastapi_app"})

def test_run_django_stack(fake_miles_context):
    ctx_obj, logger = fake_miles_context
    runner = CliRunner()
    result = runner.invoke(run, ["mydjango", "--stack", "django_app"], obj=ctx_obj)

    assert result.exit_code == 0
    assert "Scaffolding project 'mydjango' using stack 'django_app'" in result.output

def test_run_azure_hybrid_stack(fake_miles_context):
    ctx_obj, logger = fake_miles_context
    runner = CliRunner()
    result = runner.invoke(run, ["myhybrid", "--stack", "azure-hybrid"], obj=ctx_obj)

    assert result.exit_code == 0
    assert "Scaffolding project 'myhybrid' using stack 'azure-hybrid'" in result.output

def test_run_default_stack(fake_miles_context):
    ctx_obj, logger = fake_miles_context
    runner = CliRunner()
    result = runner.invoke(run, ["mydefault"], obj=ctx_obj)

    assert result.exit_code == 0
    assert "Scaffolding project 'mydefault' using stack 'all'" in result.output

def test_invalid_stack_value(fake_miles_context):
    ctx_obj, logger = fake_miles_context
    runner = CliRunner()
    result = runner.invoke(run, ["badproject", "--stack", "invalid"], obj=ctx_obj)

    assert result.exit_code != 0
    assert "Invalid value for '--stack'" in result.output
