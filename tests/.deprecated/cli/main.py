# mileslib/cli/main.py
import click
import sys
from pathlib import Path
# Add project root to sys.path manually
sys.path.append(str(Path(__file__).resolve().parents[2]))

from tests.mileslib_core import sm

from cli.commands import init_project as init
from cli.commands import render_test_boilerplate as test
from cli.commands import render_cli_boilerplate as cmdgn

@click.group(
    context_settings={"help_option_names": []},  # disable default --help
    invoke_without_command=True
)
@click.option("--help", "-h", "show_help", is_flag=True, is_eager=True, expose_value=True, help="Show this message and exit.")
@click.option("--config", is_flag=True, help="Show Config aliases help.")
@click.option("--logger", is_flag=True, help="Show Logger aliases help.")
@click.option("--requests", is_flag=True, help="Show Requests aliases help.")
@click.option("--deps", is_flag=True, help="Show Dependency aliases help.")
@click.option("--error", is_flag=True, help="Show ErrorHandling aliases help.")
@click.option("--paths", is_flag=True, help="Show Path aliases help.")
def cli(ctx, show_help, config, logger, requests, deps, error, paths):
    """MilesLib CLI for initializing projects and generating test/CLI stubs."""
    ctx.ensure_object(dict)

    if ctx.invoked_subcommand is None and show_help:
        click.echo(ctx.get_help())
        if config:
            click.echo(sm.CONFIG_USAGE.strip())
        if logger:
            click.echo(sm.LOGGER_USAGE.strip())
        if requests:
            click.echo(sm.REQUESTS_USAGE.strip())
        if deps:
            click.echo(sm.DEPENDENCIES_USAGE.strip())
        if error:
            click.echo(sm.ERROR_USAGE.strip())
        if paths:
            click.echo(sm.PATH_USAGE.strip())
        ctx.exit()

cli.add_command(init.run, name="init")
cli.add_command(test.run, name="render")
cli.add_command(cmdgn.run, name="generate-cli")
