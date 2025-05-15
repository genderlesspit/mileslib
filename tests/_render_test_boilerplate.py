#!/usr/bin/env python3
import sys
from pathlib import Path
import click
from jinja2 import Environment, FileSystemLoader

# point at your repo root so `from staticmethods import …` still works
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from staticmethods import StaticMethods as sm


@click.command(context_settings={"ignore_unknown_options": True})
@click.argument("classname", metavar="classname")
@click.option(
    "--mainname",
    default="Main",
    show_default=True,
    help="Optional name for the main class (used for {{ mainname }})",
)
def render_test_boilerplate(classname: str, mainname: str):
    """
    CLI to render a Python boilerplate class from a Jinja2 template into tests/.dev/.

    Usage:
      python tests/_render_test_boilerplate.py MyClassName --mainname Main

    This renders:
      {pdir}/tests/_test_boilerplate.j2  →  {pdir}/tests/.dev/test_<classname>.py
    """
    # --- exactly your original paths: ---
    pdir = ROOT
    tpl_path = sm.validate_file(pdir / "tests" / "_test_boilerplate.j2")
    out_dir  = pdir / "tests" / ".dev"
    sm.validate_directory(out_dir)

    # set up Jinja2 the “correct” way
    env = Environment(
        loader=FileSystemLoader(str(tpl_path.parent)),
        autoescape=False,  # no HTML auto-escaping for Python code
    )
    template = env.get_template(tpl_path.name)

    rendered = template.render(
        classname=classname,
        mainname=mainname,
    )

    out_file = out_dir / f"test_{classname.lower()}.py"
    out_file.write_text(rendered, encoding="utf-8")
    click.echo(f"✅ Created: {out_file}")


if __name__ == "__main__":
    render_test_boilerplate(classname=input("classname= "))
