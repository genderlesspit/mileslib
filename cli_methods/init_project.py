import shutil
import textwrap
from pathlib import Path

import click

from context import milescontext as mc
from util import milesutil as mu


def init_project(ctx, project_name: str):
    """
    Initializes a new Django+MilesLib project scaffold under GLOBAL_ROOT.

    1. Create an empty project directory.
    2. Run `django-admin startproject <django_name> .` inside it.
    3. Create _tests/, write config/.env, and scaffold .gitignore, requirements.txt, README.md.
    """

    # ─── Path Setup ─────────────────────────────────────────────────────────
    raw_root = Path(mc.gvar.GLOBAL_ROOT) / project_name
    try:
        root = mu.validate_directory(raw_root)
        proj_root = mu.validate_directory(root)
        proj_str = proj_root.resolve()
    except Exception as e:
        click.echo(f"[init] Directory validation failed: {e}", err=True)
        raise click.Abort()

    django_name = f"{project_name}_django"
    cfg_path = proj_root / f"mileslib_{project_name}_settings.toml"
    tests_dir = proj_root / "_tests"
    db_name = f"{project_name}_db"

    proj_details_list = {
        "project_name": project_name,
        "project_root": str(proj_root),
        "config_path": str(cfg_path),
        "tests_dir": str(tests_dir),
        "django_name": django_name,
        "database_name": db_name,
    }
    click.echo(f"[debug] raw proj_details_list: {proj_details_list}")

    # ─── Inner scaffolding functions ─────────────────────────────────────────

    def init_django():
        """
        Run `django-admin startproject <django_name> .` inside proj_root.
        The directory must remain empty at this point.
        """
        click.echo("[init] Starting Django scaffold...")
        mu.PythonDependencies.try_import("django")
        if any(proj_root.iterdir()):
            raise RuntimeError(f"Expected '{proj_str}' to be empty before `startproject`.")
        mu.run(
            ["django-admin", "startproject", django_name, "."],  # ← add `.`
            cwd=proj_root
        )


    def init_folders():
        """
        Create the _tests/ subdirectory under proj_root.
        """
        mu.validate_directory(tests_dir)

    def init_config_file():
        """
        Write the TOML config file using MilesContext.
        """
        mc.cfg.write(path=cfg_path, set=proj_details_list)
        for key, val in proj_details_list.items():
            mc.env.write(f"{project_name}.{key}", str(val), replace_existing=True)

    def scaffold_basics():
        """
        Create .gitignore, requirements.txt, and README.md under proj_root.
        """
        (proj_root / ".gitignore").write_text(
            textwrap.dedent("""\
                __pycache__/
                *.pyc
                *.log
                .env
                .DS_Store
                db.sqlite3
                /postgres_data/
                /tmp/
                .pytest_cache/
                .venv/
                .mypy_cache/
                *.sqlite3
            """),
            encoding="utf-8"
        )
        (proj_root / "requirements.txt").write_text(
            "# Add your project dependencies here\n", encoding="utf-8"
        )
        (proj_root / "README.md").write_text(
            f"# {project_name}\n\nInitialized with MilesLib.\n", encoding="utf-8"
        )

    # ─── Execute all steps ───────────────────────────────────────────────────
    try:
        init_django()
        init_folders()
        init_config_file()
        scaffold_basics()
        click.echo(f"[init] Project '{project_name}' created at: {proj_str}")
    except Exception as e:
        click.echo(f"[error] Initialization failed: {e}", err=True)
        if root.exists():
            shutil.rmtree(str(root))
        raise click.Abort()
