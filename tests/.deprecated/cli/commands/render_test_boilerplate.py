#!/usr/bin/env python3
import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from tests.mileslib_core import StaticMethods as sm
import click

def render_boilerplate(classname: str, mainname: str = "Main", pdir=None, logger=None):
    """Render a test file for a given class using a Jinja2 template."""
    pdir = Path(pdir or os.getcwd)
    tpl_path = sm.validate_file(pdir / "config" / "_test_boilerplate.j2")
    out_dir  = pdir / "tests" / ".dev"
    sm.validate_directory(out_dir)

    env = Environment(loader=FileSystemLoader(str(tpl_path.parent)), autoescape=False)
    template = env.get_template(tpl_path.name)

    rendered = template.render(classname=classname, mainname=mainname)

    out_file = out_dir / f"test_{classname.lower()}.py"
    out_file.write_text(rendered, encoding="utf-8")

    if logger:
        logger.info("Test boilerplate created", extra={"class_name": classname, "path": str(out_file)})

    click.echo(f"✅ Created: {out_file}")

@click.command(context_settings={"ignore_unknown_options": True})
@click.argument("classname")
@click.option(
    "--mainname",
    default="PlaceholderMain",
    show_default=True,
    help="Optional name for the main class (used for {{ mainname }})",
)
@click.pass_context
def run(ctx, classname: str, mainname: str):
    """CLI wrapper for test boilerplate rendering."""
    miles = ctx.obj.get(, "miles"
    render_boilerplate(pdir=miles.pdir, classname=classname, mainname=mainname, logger=miles.logger if miles else None)

if __name__ == "__main__":
    run()
