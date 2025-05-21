import click
from pathlib import Path
from mileslib import MilesLib
from mileslib import sm, log

def init(project_name: str):
    pdir = Path.cwd() / project_name
    log.info("Scaffolding project", extra={"project_name": project_name, "pdir": str(pdir)})
    click.echo(f"Scaffolding project '{project_name}' in {pdir}")

    cfg_dir = sm.validate_directory(pdir / "config")
    sm.ensure_file_with_default(cfg_dir / "settings.toml", default="[default]\nvalid = true\n")
    sm.ensure_file_with_default(cfg_dir / ".env", default="TOKEN=changeme\n")
    sm.Config.build(pdir=pdir)

@click.command()
@click.argument("project_name")
@click.pass_context
def run(ctx, project_name: str):
    """Scaffolds a new MilesLib-compatible project by name."""
    miles: MilesLib = ctx.obj["miles"]
    init(project_name=project_name)
