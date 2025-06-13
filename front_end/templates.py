import importlib
import importlib.util
import types
from functools import cached_property
from pathlib import Path
from bs4 import BeautifulSoup
from loguru import logger as log


class Templates:
    def __init__(self, _project):
        from front_end.htmxlib import HTMXServer
        self.project = _project

    @cached_property
    def htmx_server(self):
        from front_end.htmxlib import HTMXServer
        return HTMXServer.get(self.project, self.project.htmx_host, self.project.htmx_port)

    @cached_property
    def htmx_meta(self):
        from bs4 import BeautifulSoup
        return BeautifulSoup(self.htmx_server.meta, "html.parser")

    @cached_property
    def templates_path(self) -> Path:
        path = self.project.path / "templates"
        path.mkdir(exist_ok=True)
        return path

    @cached_property
    def templates_dict(self) -> dict:
        templates_dict = {}
        ext = ".html"
        files = list(self.templates_path.rglob(f"*{ext}"))
        for file in files:
            file_path = Path(file)
            name = file_path.name.removesuffix(ext)
            templates_dict[name] = str(file_path)
        return templates_dict

    def get(self, name: str) -> str:
        if not isinstance(name, str): raise TypeError("Name must be a string")
        file_path = Path(self.templates_dict.get(name))
        if not file_path: raise FileNotFoundError(f"No template named '{name}'")
        with file_path.open("r", encoding="utf-8") as f: soup = BeautifulSoup(f, "html.parser")
        meta = self.htmx_meta
        if soup.head: soup.head.insert(0, meta)
        elif soup.body: soup.body.insert(0, meta)
        else: soup.insert(0, meta)

        return str(soup)

    @cached_property
    def htmx_path(self) -> Path:
        path = self.project.path / "htmx"
        path.mkdir(exist_ok=True)
        return path

    @cached_property
    def routes(self) -> dict[str, types.FunctionType]:
        registered = {}

        for path in self.htmx_path.glob("*.py"):
            module_name = path.stem
            spec = importlib.util.spec_from_file_location(module_name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            for name, fn in vars(mod).items():
                if name.startswith("htmx_") and isinstance(fn, types.FunctionType):
                    route_name = name.removeprefix("htmx_")
                    registered[route_name] = fn

        return registered
