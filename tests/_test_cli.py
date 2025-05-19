# File: tests/.dev/cli_placeholder.py
import click
from click.testing import CliRunner
import pytest

@click.command()
@click.argument("arg1")
@click.argument("arg2")
@click.option("--flag", is_flag=True, help="Boolean flag for control")
@click.option("--count", type=int, default=3, help="Number of retries")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
@click.option("--dry-run", is_flag=True, help="Simulate execution")
@click.option("--fail", is_flag=True, help="Trigger intentional failure")
@click.pass_context
def placeholder(ctx, arg1, arg2, flag, count, verbose, dry_run, fail):
    """
    Placeholder CLI command for templating and test.
    """
    if fail:
        raise click.ClickException("Intentional failure")

    if verbose:
        click.echo("[verbose] Placeholder started")
        click.echo(f"arg1={arg1}, arg2={arg2}, flag={flag}, count={count}")

    if dry_run:
        click.echo("[dry-run] No changes made.")
        return

    click.echo("placeholder called")

# --- Inline test suite ---

def test_placeholder_invokes():
    runner = CliRunner()
    result = runner.invoke(placeholder, ["val1", "val2", "--flag", "--count", "2", "--verbose"])
    assert result.exit_code == 0
    assert "placeholder called" in result.output

def test_placeholder_shows_help():
    runner = CliRunner()
    result = runner.invoke(placeholder, ["--help"])
    assert result.exit_code == 0
    assert "Usage" in result.output
    assert placeholder.__doc__.strip()[:10] in result.output

def test_placeholder_missing_required_argument():
    runner = CliRunner()
    result = runner.invoke(placeholder, [])
    assert result.exit_code != 0
    assert "Missing argument" in result.output

def test_placeholder_dry_run():
    runner = CliRunner()
    result = runner.invoke(placeholder, ["x", "y", "--dry-run"])
    assert result.exit_code == 0
    assert "[dry-run]" in result.output

def test_placeholder_intentional_failure():
    runner = CliRunner()
    result = runner.invoke(placeholder, ["x", "y", "--fail"])
    assert result.exit_code != 0
    assert "Intentional failure" in result.output

def test_placeholder_flag_behavior():
    runner = CliRunner()
    result = runner.invoke(placeholder, ["x", "y", "--verbose"])
    assert result.exit_code == 0
    assert "[verbose]" in result.output
