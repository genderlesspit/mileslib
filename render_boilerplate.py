import argparse
from pathlib import Path
from jinja2 import Template
import os
from staticmethods import StaticMethods as sm
import pytest

class Main:
    def __init__(self, pdir: Path):
        """Parent instance of all MilesLib Classes.
        :param pdir: Project directory, usually os.getcwd(), unless specified by config files.
        """
        pdir = pdir or os.getcwd()
        self.pdir = sm.validate_instance_directory(pdir)
        self.args = self._parse_args()

        self.jinja_boiler_plate_path = sm.validate_file(
            self.pdir / "tests" / "_test_boilerplate.j2"
        )

        output_dir = self.args.output_dir or "."
        self.output_path = Path(output_dir) / f"{self.args.classname.lower()}.py"
        sm.validate_directory(self.output_path.parent)

        self._render_template()

    def _parse_args(self):
        parser = argparse.ArgumentParser(description="Render class boilerplate from Jinja2 template.")
        parser.add_argument("classname", help="The name of the target class to generate.")
        parser.add_argument("--mainname", default="Main", help="The name of the main class.")
        parser.add_argument("--output-dir", default=".", help="Directory to write the rendered file.")
        return parser.parse_args()

    def _render_template(self):
        with self.jinja_boiler_plate_path.open("r", encoding="utf-8") as f:
            template = Template(f.read())

        rendered = template.render(
            classname=self.args.classname,
            mainname=self.args.mainname,
        )

        self.output_path.write_text(rendered, encoding="utf-8")
        print(f"✅ Boilerplate for '{self.args.classname}' written to: {self.output_path}")

if __name__ == "__main__":
    Main(pdir=Path(os.getcwd()))