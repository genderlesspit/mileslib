import os
import argparse
import sys
from pathlib import Path
from jinja2 import Template

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from util.staticmethods import StaticMethods as sm

class RenderTestBoilerPlate:
    """
    CLI to render a Python boilerplate class from a Jinja2 template into tests/.dev/.

    Usage:
        python tests/_render_test_boilerplate MyClassName --mainname Main

    This renders:
        {pdir}/tests/_test_boilerplate.j2  →  {pdir}/tests/.dev/myclassname.py
    """

    def __init__(self, pdir: Path):
        """
        Args:
            pdir (Path): The project root directory (typically `os.getcwd()`).
        """
        self.pdir = sm.validate_instance_directory(pdir)
        self.args = self._parse_args()

        # Input template and output destination (hardcoded to project-relative paths)
        self.template_path = sm.validate_file(self.pdir / "tests" / "_test_boilerplate.j2")
        self.output_path = self.pdir / "tests" / ".dev" / f"{self.args.classname.lower()}.py"

        # Ensure output directory exists
        sm.validate_directory(self.output_path.parent)

        self._render_template()

    @staticmethod
    def _parse_args():
        """
        Parses CLI arguments for class and main names.

        Returns:
            argparse.Namespace: Parsed arguments.
        """
        parser = argparse.ArgumentParser(
            description="Render a Python class file from a Jinja2 template (into tests/.dev/)",
            epilog="""
Example:
    python tests/_render_test_boilerplate.py MyNewClass --mainname Main
Output:
    tests/.dev/test_mynewclass.py
"""
        )
        parser.add_argument(
            "classname", help="Name of the class to generate (used for {{ classname }})"
        )
        parser.add_argument(
            "--mainname", default="Main", help="Optional name for the main class (default: Main)"
        )
        return parser.parse_args()

    def _render_template(self):
        """
        Loads and renders the template with provided names.
        """
        with self.template_path.open("r", encoding="utf-8") as f:
            template = Template(f.read())

        rendered = template.render(
            classname=self.args.classname,
            mainname=f"test_{self.args.mainname}"
        )

        self.output_path.write_text(rendered, encoding="utf-8")
        print(f"✅ Created: {self.output_path}")

if __name__ == "__main__":
    Main(pdir=Path(os.getcwd()))
