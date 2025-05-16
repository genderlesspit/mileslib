# mileslib/cli/main.py
import click
from mileslib import MilesLib
from cli.commands import init_project, render_test_boilerplate

@click.group()
@click.pass_context
def cli(ctx):
    ctx.ensure_object(dict)
    ctx.obj["miles"] = MilesLib()  # ← instantiates logger internally

@cli.command()
@click.argument("project_name")
@click.pass_context
def init(ctx, project_name):
    miles = ctx.obj["miles"]
    log = miles.logger
    log.info("CLI Init called", project_name=project_name)
    init_project.run(project_name, logger=log)

@cli.command()
@click.argument("class_name")
@click.pass_context
def render(ctx, class_name):
    miles = ctx.obj["miles"]
    log = miles.logger
    log.info("CLI Render called", class_name=class_name)
    render_test_boilerplate.run(class_name, logger=log)
