import click
from jinja2 import Environment, FileSystemLoader
import pytest
from click.testing import CliRunner
from pathlib import Path
import shutil
import tempfile

@click.command()
@click.argument("command_name")
@click.argument("args", nargs=-1)
@click.option("--opt", multiple=True, help="Options in format name:type:default:help")
@click.option("--docstring", default="CLI command", help="Docstring for the command.")
@click.pass_context
def run(ctx, command_name, args, opt, docstring):
    miles = ctx.obj["miles"]
    logger = miles.logger
    pdir = miles.pdir

    options = []
    for o in opt:
        try:
            name, typ, default, help_text = o.split(":")
            options.append({
                "name": name,
                "type": typ,
                "default": default,
                "help": help_text
            })
        except ValueError:
            raise click.BadParameter(f"Option must be in format name:type:default:help → {o}")

    env = Environment(loader=FileSystemLoader(pdir / "config"))
    cli_tpl = env.get_template("_cli_command_template.j2")

    context = {
        "command_name": command_name,
        "args": args,
        "options": options,
        "docstring": docstring
    }

    cli_code = cli_tpl.render(**context)

    out_dir = pdir / "tests" / ".dev"
    out_dir.mkdir(parents=True, exist_ok=True)

    cli_path = out_dir / f"cli_{command_name}.py"
    cli_path.write_text(cli_code, encoding="utf-8")

    logger.info("Generated CLI + embedded test", extra={"command": command_name})
    click.echo(f"CLI with test written to: {cli_path}")

@pytest.fixture
def temp_miles(monkeypatch):
    from types import SimpleNamespace
    temp_dir = Path(tempfile.mkdtemp())

    logs = []
    def fake_logger_info(msg, extra=None):
        logs.append((msg, extra))

    miles = SimpleNamespace(
        pdir=temp_dir,
        logger=SimpleNamespace(info=fake_logger_info)
    )

    ctx = {"miles": miles}
    yield ctx, logs, temp_dir

    shutil.rmtree(temp_dir)

@pytest.fixture
def template_fixture(temp_miles):
    ctx, _, pdir = temp_miles
    config_dir = pdir / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    template_path = config_dir / "_cli_command_template.j2"
    template_path.write_text("{{ command_name }} {{ args }} {{ options }}", encoding="utf-8")
    return temp_miles

def test_generate_cli_success(template_fixture):
    ctx, logs, pdir = template_fixture
    runner = CliRunner()
    result = runner.invoke(run, [
        "deploy",
        "region", "env",
        "--opt", "force:bool:True:Force it",
        "--docstring", "Deploy command"
    ], obj=ctx)

    assert result.exit_code == 0
    assert "cli_deploy.py" in result.output
    output_file = pdir / "tests" / ".dev" / "cli_deploy.py"
    assert output_file.exists()
    assert "deploy" in output_file.read_text()
    assert any("Generated CLI + embedded test" in msg for msg, _ in logs)

def test_generate_cli_malformed_opt(template_fixture):
    ctx, logs, _ = template_fixture
    runner = CliRunner()
    result = runner.invoke(run, [
        "failcase",
        "arg1",
        "--opt", "badformat"
    ], obj=ctx)

    assert result.exit_code != 0
    assert "Option must be in format" in result.output

def test_generate_cli_creates_directory(template_fixture):
    ctx, _, pdir = template_fixture
    output_dir = pdir / "tests" / ".dev"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    assert not output_dir.exists()

    runner = CliRunner()
    result = runner.invoke(run, [
        "testdir",
        "x",
        "--opt", "flag:bool:False:A test flag"
    ], obj=ctx)

    assert result.exit_code == 0
    assert (output_dir / "cli_testdir.py").exists()
