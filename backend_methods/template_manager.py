from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from util import milesutil as mu
from context import milescontext as mc


class TemplateManager:
    _env = None
    _template_dir = mc.gvar.GLOBAL_TEMPLATES_DIR or mc.cfg.get("template_directory")

    @staticmethod
    def setup(path: Path = _template_dir):
        """
        Initialize the Jinja2 environment and template path.

        Args:
            path (Path): Path to the directory containing Jinja2 templates.
        """
        templ = TemplateManager
        if not path.exists():
            mu.Path.validate_directory(path)
        if templ._env is None:
            templ._env = Environment(
                loader=FileSystemLoader(str(path)),
                autoescape=select_autoescape(['html', 'xml', 'jinja', 'j2'])
            )
        if templ and path is not None:
            print(f"Template dir recognized: {path}")
            print(f"Template environment initialized: {templ}")
            return templ._env
        else:
            raise RuntimeError("Could not initialize j2 template manager!")

    @staticmethod
    def render_to_file(template_name: str, context: dict, output_path: Path, overwrite: bool = False):
        """
        Render a Jinja2 template to a file.

        Args:
            template_name (str): Filename of the Jinja2 template (e.g. 'README.md.j2').
            context (dict): Variables to render in the template.
            output_path (Path): Where to write the rendered file.
            overwrite (bool): Whether to overwrite if file already exists.
        """
        templ = TemplateManager
        env = templ.setup()

        if output_path.exists() and not overwrite:
            print(f"[template] {output_path} exists, skipping.")
            return

        template = env.get_template(template_name)
        rendered = template.render(**context)
        output_path.write_text(rendered, encoding="utf-8")
        print(f"[template] Wrote: {output_path}")
