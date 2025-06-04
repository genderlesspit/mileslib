import inspect
import shutil
import textwrap
from functools import wraps
from pathlib import Path
import click
import mileslib as ml
import util


class ProjectAwareGroup(click.Group):
    def format_commands(self, ctx, formatter):
        commands = self.list_commands(ctx)
        if not commands:
            return

        global_cmds, project_grps = [], []
        for name in commands:
            cmd = self.get_command(ctx, name)
            if isinstance(cmd, click.Group) and name in CLIDecorator._projects:
                project_grps.append((name, cmd))
            else:
                global_cmds.append((name, cmd))

        # Global
        if global_cmds:
            with formatter.section("Global Commands"):
                entries = [(n, c.help or "") for n, c in global_cmds]
                try:
                    formatter.write_dl(entries)
                except TypeError:
                    for n, h in entries:
                        formatter.write_text(f"  {n}\t{h}\n")

        # Per-project
        for pname, grp in project_grps:
            with formatter.section(f"Project Commands: {pname}"):
                subs = [(n, c.help or "") for n, c in grp.commands.items()]
                try:
                    formatter.write_dl(subs)
                except TypeError:
                    for n, h in subs:
                        formatter.write_text(f"  {n}\t{h}\n")

class CLIDecorator:
    _global = ProjectAwareGroup(invoke_without_command=True)
    _projects = {}
    _project_only_cmds = []         # ← collect these here
    _registered = False

    @staticmethod
    @ml.mileslib(retry=False)
    def auto_register_groups():
        """
        Auto-registers Click command groups for each valid project
        with a config TOML file.
        """
        if CLIDecorator._registered:
            print("[CLIDecorator] Skipping auto_register_groups — already called.")
            return
        CLIDecorator._registered = True

        for name, path in ml.putil.discover_projects():
            print(f"[auto_register] Registering project group: {name}")

            def make_group(name: str, path: Path):
                @click.group(name=name, cls=ProjectAwareGroup)
                @click.pass_context
                def _grp(ctx):
                    ctx.ensure_object(dict)
                    ctx.obj["project_name"] = name
                    ctx.obj["project_path"] = path
                    ml.putil.select_project(name=name, path=path)
                    print(f"[mileslib_settings.toml] Active project set to: {name}")

                return _grp

            if name not in CLIDecorator._projects:
                grp = make_group(name, path)
                CLIDecorator._projects[name] = grp
                CLIDecorator._global.add_command(grp)

        for cmd in CLIDecorator._project_only_cmds:
            for grp in CLIDecorator._projects.values():
                grp.add_command(cmd)

    @staticmethod
    def mileslib_cli(*, project_only: bool = False, **mileslib_kwargs):
        def decorator(fn):
            if isinstance(fn, staticmethod):
                fn = fn.__func__

            # Step A: wrap with your @mileslib
            fn = ml.mileslib(**mileslib_kwargs)(fn)

            # Step B: build the Click wrapper that only forwards args your fn wants
            @click.pass_context
            @wraps(fn)
            def wrapper(ctx, *args, **kwargs):
                sig = inspect.signature(fn)
                accepted = set(sig.parameters) - {"ctx"}
                safe_kwargs = {k: v for k, v in kwargs.items() if k in accepted}
                return fn(ctx, *args, **safe_kwargs)

            # Step C: attach click arguments/options
            sig = inspect.signature(fn)
            for param in reversed(list(sig.parameters.values())[1:]):
                ptype = str if param.annotation is inspect._empty else param.annotation
                default = None if param.default is inspect._empty else param.default
                dash = param.name.replace("_", "-")
                if default is None:
                    wrapper = click.argument(param.name, type=ptype)(wrapper)
                else:
                    wrapper = click.option(f"--{dash}", default=default, type=ptype)(wrapper)

            # Step D: turn into a Click command
            cmd_name = fn.__name__.replace("_", "-")
            command = click.command(name=cmd_name, help=fn.__doc__)(wrapper)

            if project_only:
                # collect it for later
                CLIDecorator._project_only_cmds.append(command)
            else:
                # immediately stick it in the global group
                CLIDecorator._global.add_command(command)

            return command

        return decorator

# alias so your decorators don’t change:
mileslib_cli = CLIDecorator.mileslib_cli

class CLI:
    """
    MilesLib CLI orchestrator.
    """
    def __init__(self):
        # also in case someone does CLI().entry() directly
        CLIDecorator.auto_register_groups()
        self.cli = CLIDecorator._global

    @ml.mileslib
    def entry(self):
        # no custom argv logic—let Click do the routing
        return self.cli()

    class CMDManager:
        class Global:
            @staticmethod
            @mileslib_cli(project_only = False)
            def diagnostics_check(ctx, tool: str):
                """
                CLI: Runs diagnostic checks for a list of tools.

                Args:
                    tool (list[str]): List of tools to check. Use multiple --tool flags.

                Examples:
                    $ python -m mileslib diagnostics-check --tool milesazure --tool docker
                """
                ml.clim.check_dependencies(tool)

            @staticmethod
            @mileslib_cli(project_only=False)  # or True, depending on scope
            def init_project(ctx, project_name: str):
                """
                Initializes a new project folder with Django scaffold and config.

                Args:
                    project_name (str): Name of the project.

                Raises:
                    click.Abort: On validation or milessubprocess failure.
                """
                sanny = util.sanitization.Sanitization.standard(project_name)
                ml.clim.init_project(ctx, sanny)

        class Project:
            @staticmethod
            @mileslib_cli(project_only=True)
            def start(ctx):
                from cli_methods import init_azure
                return init_azure.init_azure(ctx)

            class SecretsBootstrap:
                @staticmethod
                @mileslib_cli(project_only=True)
                def init_vault(ctx):
                    """
                    CLI entrypoint to initialize Azure Key Vault for the current project.

                    This will:
                    - Validate environment and Azure config
                    - Create the vault if missing
                    - Set up access policies
                    - Initialize the Secrets client for use

                    Args:
                        ctx (click.Context): Click context with project_name and project_path

                    Side Effects:
                        - Ensures vault exists and is usable
                        - Updates KEY_VAULT_URL in environment
                        - Logs status
                    """
                    project_name = ctx.obj["project_name"]
                    print(f"[SecretsBootstrap] Initializing vault for: {project_name}")
                    raise NotImplementedError

            class Database:
                """
                CLI entrypoints for Azure PostgreSQL setup via MilesLib.
                """

                @staticmethod
                @mileslib_cli(project_only=True)
                def init_database(ctx):
                    """
                    Initializes Azure PostgreSQL for the active project.

                    - Checks for existing DB
                    - Creates a flexible server if needed
                    - Prints FQDN and admin login info
                    """
                    project = ctx.obj["project_name"]
                    raise NotImplementedError

            class DockerSetup:
                """
                Handles Docker-based service scaffolding and container management for MilesLib projects.
                Supports PostgreSQL and future add-ons like Redis, pgAdmin, Celery, etc.
                """

                @staticmethod
                @mileslib_cli(project_only=True)
                def docker_setup(ctx):
                    """
                    CLI entrypoint for scaffolding and launching Docker-based infrastructure for the project.

                    Responsibilities:
                    - Creates `docker-compose.yml` with service blocks for PostgreSQL, Redis, and optional Flower.
                    - Generates a `.env` file populated with project-specific environment variables.
                    - Validates Docker availability and prompts to start services.
                    - Provides instructions for managing Docker containers via CLI.

                    Args:
                        ctx (click.Context): Click context, should contain project_name and project_path.

                    Side Effects:
                        - Writes `docker-compose.yml` and `.env` to the project directory.
                        - Starts containers using `docker-compose up -d`.
                        - Logs success or error messages for service initialization.

                    """

                @staticmethod
                def generate_compose_file(project_name: str, output_path: Path, settings: dict):
                    """
                    Writes a docker-compose.yml to the given output path using provided DB settings.

                    Args:
                        project_name (str): The name of the project (used in container names).
                        output_path (Path): The directory where the docker-compose.yml should be created.
                        settings (dict): Must include db_name, db_user, db_pass.

                    Side Effects:
                        - Creates docker-compose.yml file in output_path.
                    """

                @staticmethod
                def generate_compose_file(project_name: str, output_path: Path, settings: dict):
                    """
                    Writes a docker-compose.yml to the given output path using provided DB settings.

                    Args:
                        project_name (str): The name of the project (used in container names).
                        output_path (Path): The directory where the docker-compose.yml should be created.
                        settings (dict): Must include db_name, db_user, db_pass.

                    Side Effects:
                        - Creates docker-compose.yml file in output_path.
                    """

                @staticmethod
                def generate_env_file(output_path: Path, settings: dict):
                    """
                    Writes a .env file with database environment variables used by Docker.

                    Args:
                        output_path (Path): Directory where the .env file should be saved.
                        settings (dict): Contains DB credentials and project-specific environment values.

                    Side Effects:
                        - Creates or overwrites .env file.
                    """

                @staticmethod
                def start_docker_services(project_path: Path, services: list[str] = None):
                    """
                    Runs `docker-compose up -d` in the project path to start the desired services.

                    Args:
                        project_path (Path): Path to the root of the MilesLib project.
                        services (list[str], optional): Services to start. Defaults to ['db'].

                    Raises:
                        milessubprocess.CalledProcessError if Docker fails to start.
                    """

                @staticmethod
                def stop_docker_services(project_path: Path, services: list[str] = None):
                    """
                    Stops running Docker containers for the given services.

                    Args:
                        project_path (Path): Path to the project directory.
                        services (list[str], optional): Services to stop. Defaults to ['db'].
                    """

                @staticmethod
                def remove_docker_services(project_path: Path):
                    """
                    Stops and removes all Docker containers, networks, and volumes created by the project.

                    Args:
                        project_path (Path): Path to the root project directory with docker-compose.yml.

                    Raises:
                        milessubprocess.CalledProcessError if teardown fails.
                    """

                @staticmethod
                def check_postgres_ready(timeout: float = 10.0) -> bool:
                    """
                    Checks whether PostgreSQL is available and accepting connections on localhost:5432.

                    Args:
                        timeout (float): Timeout in seconds to wait for readiness.

                    Returns:
                        bool: True if PostgreSQL is reachable, False otherwise.
                    """

            class DjangoSetup:
                """
                Handles Django-specific setup for MilesLib projects:
                - Injects PostgreSQL settings into Django's settings.py
                - Scaffolds Azure AD (MSAL) authentication
                - Ensures required apps, middlewares, and auth backends are added
                """

                @staticmethod
                def inject_postgres_settings(settings_path: Path, db_settings: dict):
                    """
                    Modifies the Django `settings.py` file to configure PostgreSQL.

                    Args:
                        settings_path (Path): Path to the Django settings.py file.
                        db_settings (dict): Dictionary containing db_name, db_user, db_pass, host, port.

                    Side Effects:
                        - Replaces existing DATABASES config with PostgreSQL block.
                        - Writes changes in-place to settings.py.
                    """

                @staticmethod
                def add_msal_integration(settings_path: Path, project_root: Path):
                    """
                    Adds MSAL configuration to Django settings and scaffolds necessary MSAL logic.

                    Args:
                        settings_path (Path): Path to the Django settings.py file.
                        project_root (Path): Root directory of the Django project.

                    Side Effects:
                        - Adds AAD client ID, tenant ID, redirect URI to settings.py.
                        - Adds `django_microsoft_auth` or custom backend if required.
                        - Optionally creates auth views / urls / middleware hooks.
                    """

                @staticmethod
                def ensure_required_apps(settings_path: Path):
                    """
                    Ensures `INSTALLED_APPS` includes needed packages for DB and MSAL integration.

                    Args:
                        settings_path (Path): Path to settings.py.

                    Side Effects:
                        - Adds entries like 'django.contrib.sites', 'microsoft_auth', etc.
                    """

                @staticmethod
                def inject_auth_backends(settings_path: Path):
                    """
                    Appends required auth backends (e.g., Microsoft AAD) to `AUTHENTICATION_BACKENDS`.

                    Args:
                        settings_path (Path): Path to settings.py.

                    Side Effects:
                        - Adds 'microsoft_auth.backends.MicrosoftAuthenticationBackend'
                          or your custom backend.
                    """

                @staticmethod
                def create_msal_login_urls(project_root: Path):
                    """
                    Creates Django URL routes and view stubs for handling MSAL login, callback, and logout.

                    Args:
                        project_root (Path): Root of the Django app (where urls.py and views.py exist).

                    Side Effects:
                        - Adds login/logout/callback URL patterns to urls.py.
                        - Creates views.py entries or MSAL-compatible templates if not present.
                    """

                @staticmethod
                def set_env_settings_reference(settings_path: Path):
                    """
                    Modifies `settings.py` to reference secrets/env variables from MilesContext.

                    Args:
                        settings_path (Path): Path to settings.py.

                    Side Effects:
                        - Replaces hardcoded credentials with `os.getenv()` or `MilesContext.secrets.get()`.
                    """

            class BackgroundTasks:
                """
                Handles background task infrastructure for MilesLib projects using Celery, Redis, and optionally Flower.

                Responsibilities:
                - Generates celery.py and tasks.py in the project root
                - Adds Redis to docker-compose
                - Adds optional Flower monitoring UI
                - Injects Django or FastAPI-compatible Celery config
                """

                @staticmethod
                @mileslib_cli(project_only=True)
                def setup_background_tasks(ctx):
                    """
                    CLI entrypoint for setting up background task infrastructure with Celery and Redis.

                    Responsibilities:
                    - Generates `celery.py` and `tasks.py` in the Django/FastAPI project root.
                    - Adds Redis service block to `docker-compose.yml`.
                    - Optionally adds Flower service for task monitoring.
                    - Patches settings file with Celery broker/backend config.
                    - Ensures required .env variables are defined.

                    Args:
                        ctx (click.Context): Click context, expected to contain project_name and project_path.

                    Side Effects:
                        - Writes or modifies local project files and environment config.
                        - Registers Celery for asynchronous background task execution.
                        - Enables Redis-backed broker and optional Flower monitoring.
                    """

                def scaffold_celery_files(project_root: Path, project_name: str):
                    """
                    Writes `celery.py` and `tasks.py` boilerplate files in the Django project directory.

                    Args:
                        project_root (Path): Path to root of the project.
                        project_name (str): Name of the Django project to bind Celery to.

                    Side Effects:
                        - Creates celery.py entrypoint with app init.
                        - Creates tasks.py with basic example task.
                        - Adds Celery app loading in __init__.py if needed.
                    """

                @staticmethod
                def patch_settings_for_celery(settings_path: Path):
                    """
                    Modifies Django `settings.py` or FastAPI equivalent to support Celery broker and backend.

                    Args:
                        settings_path (Path): Path to the project settings.py.

                    Side Effects:
                        - Injects CELERY_BROKER_URL and CELERY_RESULT_BACKEND from env or secrets.
                        - Adds necessary Celery imports if missing.
                    """

                @staticmethod
                def add_redis_to_docker_compose(compose_path: Path):
                    """
                    Injects Redis service block into the docker-compose.yml.

                    Args:
                        compose_path (Path): Path to docker-compose.yml

                    Side Effects:
                        - Adds 'redis' service if not already present.
                        - Mounts a volume if needed.
                    """

                @staticmethod
                def add_flower_to_docker_compose(compose_path: Path):
                    """
                    Adds Flower service for real-time Celery monitoring.

                    Args:
                        compose_path (Path): Path to docker-compose.yml

                    Side Effects:
                        - Adds 'flower' service (port 5555).
                        - Links to Redis and Celery app.
                    """

                @staticmethod
                def create_env_entries(env_path: Path):
                    """
                    Ensures .env file contains required Celery/Redis environment variables.

                    Args:
                        env_path (Path): Path to the .env file.

                    Side Effects:
                        - Adds default CELERY_BROKER_URL, RESULT_BACKEND, and Flower settings.
                    """

                @staticmethod
                def test_celery_connection(project_root: Path):
                    """
                    Runs a one-off test to ensure Celery worker can connect to Redis and run tasks.

                    Args:
                        project_root (Path): Root path to where celery.py and tasks.py exist.

                    Raises:
                        RuntimeError if connection or task execution fails.
                    """

            class FrontDoorSetup:
                """
                Handles Azure Front Door setup and integration with external DNS providers like GoDaddy.
                Enables HTTPS, domain validation, and CNAME binding for custom domains.
                """

                @staticmethod
                @mileslib_cli(project_only=True)
                def setup_godaddy_dns(domain: str, subdomain: str = "www"):
                    """
                    Guides the user through configuring GoDaddy DNS to point a custom domain or subdomain
                    (e.g. www.yourdomain.com) to an Azure Front Door instance.

                    Args:
                        domain (str): The root domain managed by GoDaddy (e.g., "yourdomain.com").
                        subdomain (str, optional): The subdomain to configure (e.g., "www", "api"). Defaults to "www".

                    Side Effects:
                        - Prompts the user to create a CNAME pointing to Azure Front Door.
                        - Prompts the user to add a TXT record for domain validation.
                        - Instructs user to verify domain ownership and enable HTTPS in Azure.
                    """
                    pass

def main():
    # make sure groups exist *before* Click ever parses
    CLIDecorator.auto_register_groups()
    CLI().entry()

if __name__ == "__main__":
    main()