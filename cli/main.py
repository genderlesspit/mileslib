import click
from cli.commands import init_project, render_test_boilerplate

@click.group()
def cli():
    """MilesLib CLI Engine"""
    pass

@cli.command()
@click.argument("project_name")
def init(project_name):
    """Initialize a new project directory."""
    init_project.run(project_name)

@cli.command()
@click.argument("class_name")
def render(class_name):
    """Render a test boilerplate for a class."""
    render_test_boilerplate.run(class_name)

if __name__ == "__main__":
    cli()