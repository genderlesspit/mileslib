from mileslib import MilesLib
import cli
import click

@click.command()
@click.argument("project_name")
@click.pass_context
def run(project_name):
    """Scaffolder for various web-development stacks."""
    pass

def init(ctx, project_name):
    miles = ctx.obj["miles"]
    log = miles.logger
    log.info("CLI Init called", project_name=project_name)
    run(project_name=project_name)