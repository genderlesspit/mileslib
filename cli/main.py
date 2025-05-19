# mileslib/cli/main.py
import click
from mileslib import MilesLib
from cli.commands import init_project as init
from cli.commands import render_test_boilerplate as test
from cli.commands import render_cli_boilerplate as cmdgn

@click.group()
@click.pass_context
def cli(ctx):
    ctx.ensure_object(dict)
    ctx.obj["miles"] = MilesLib()  # ← instantiates logger internally

cli.add_command(cmd=init.run, name="init")
cli.add_command(cmd=test.run, name="render")
cli.add_command(cmd=cmdgn.run, name="generate-cli")