import click
import sys
from functools import wraps
from tests.mileslib_core import mileslib, ROOT

class CLIDecorator:
    _top_level = click.Group(invoke_without_command=True)
    _projects = {}

    @staticmethod
    def mileslib_cli(*, project_only: bool = False):
        def decorator(fn):
            name = fn.__name__.replace("_", "-")

            @click.command(name=name)
            @click.pass_context
            @wraps(fn)
            def wrapper(ctx, *args, **kwargs):
                project = ctx.obj.get("project") if ctx.obj else None
                print(f"[cli] Running command '{name}' (project={project})")
                return fn(ctx, *args, **kwargs)

            def register_top_level():
                if not project_only:
                    CLIDecorator._top_level.add_command(wrapper)

            def register_per_project():
                if not ROOT or not ROOT.exists():
                    return
                for subdir in ROOT.iterdir():
                    if (subdir / "mileslib_project_settings.toml").exists():
                        pname = subdir.name
                        if pname not in CLIDecorator._projects:
                            @click.group(name=pname)
                            @click.pass_context
                            def _group(ctx):
                                ctx.ensure_object(dict)
                                ctx.obj["project"] = pname
                                ctx.obj["project_path"] = subdir
                            CLIDecorator._projects[pname] = _group
                        CLIDecorator._projects[pname].add_command(wrapper)

            register_top_level()
            register_per_project()
            return wrapper

        return decorator

# Alias for convenience
mileslib_cli = CLIDecorator.mileslib_cli

# ──────────────────────────────────────────────────────────────
class CLI:
    """
    MilesLib CLI orchestrator.
    """

    class CMDManager:
        def __init__(self):
            self.cli = CLIDecorator._top_level

        @mileslib
        def launch(self):
            args = sys.argv[1:]
            print(f"[debug] CLI args: {args}")
            if not args or args[0].startswith("-"):
                return self.cli()
            elif args[0] in CLIDecorator._projects:
                return CLIDecorator._projects[args[0]]()
            else:
                return self.cli()

        # ──────── Top-Level Commands ─────────
        class Core:
            @staticmethod
            @mileslib_cli()
            @click.argument("project_name")
            def init(ctx, project_name):
                try:
                    print(f"[init] Creating project: {project_name}")
                except RuntimeError as e:
                    click.echo(str(e))
                    raise click.Abort()

        # ──────── Project-Scoped Commands ────────
        class Project:
            @staticmethod
            @mileslib_cli(project_only=True)
            @click.option("--repair", is_flag=True, help="Attempt to auto-repair any failed checks.")
            def diagnostic(ctx):
                try:
                    project = ctx.obj["project"]
                    path = ctx.obj["project_path"]
                    print(f"[init] Running diagnostics for {project}...")
                except Exception as e:
                    click.echo(f"[error] Diagnostic failed: {e}")
                    raise click.Abort()