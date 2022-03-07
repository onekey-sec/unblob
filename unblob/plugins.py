import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import List, Optional, Tuple

import pluggy
from structlog import get_logger

from unblob import hookspecs

# The entrypoints are defined by the to-be-loaded plugins. The version
# should be incremented whenever a backward-incompatible change is
# introduced.
SETUPTOOLS_ENTRYPOINT_NAME = "unblob_v1"

logger = get_logger()

hookimpl = pluggy.HookimplMarker("unblob")


class UnblobPluginManager(pluggy.PluginManager):
    def __init__(self):
        super().__init__("unblob")
        self.add_hookspecs(hookspecs)

    def load_setuptools_entrypoints(
        self, group: str = SETUPTOOLS_ENTRYPOINT_NAME, name: Optional[str] = None
    ):
        return super().load_setuptools_entrypoints(group, name=name)

    def import_path(self, path: Path):
        """Loads Python code from a given path.

        The following scenarios are supported based on the contents of
        ``path``:

        Single file
          Path points to a single Python file

        Multiple files
          A directory containing one or more Python files or packages.
          Files are loaded from the directory root.  Additional
          sub-directories containing Python packages (directories with
          ``__init__.py``) are loaded recursively.
        """
        logger.debug("Importing plugin modules", path=path)

        if path.is_file():
            module_name = path.stem
            to_import = [(module_name, path)]
        elif path.is_dir:
            to_import = [(p.parent.name, p) for p in path.glob("*/__init__.py")]
            to_import.extend((p.stem, p) for p in path.glob("*.py"))
        else:
            raise ValueError("Invalid plugin import path", path)

        modules = self._import_modules(to_import)
        logger.debug("Imported plugins", modules=modules)
        for module in modules:
            self.register(module)

    @classmethod
    def _import_modules(
        cls, modules_to_import: List[Tuple[str, Path]]
    ) -> List[ModuleType]:
        modules = []
        for module_name, path in modules_to_import:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if not spec or not spec.loader:
                logger.error("Invalid plugin file", path=path)
                continue

            mod = importlib.util.module_from_spec(spec)
            # This is crucial for package loading, in order to module
            # import inside a package to work.
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)
            modules.append(mod)

        return modules
