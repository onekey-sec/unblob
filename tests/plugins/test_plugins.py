from pathlib import Path

import pytest

from unblob.hookspecs import hookspec
from unblob.plugins import UnblobPluginManager

ASSETS_PATH = Path(__file__).parent / "__assets__"


class TestHookSpecs:
    @hookspec
    def hook_callback():
        pass


@pytest.fixture
def plugin_manager():
    pm = UnblobPluginManager()
    pm.add_hookspecs(TestHookSpecs)
    return pm


@pytest.mark.parametrize(
    "plugin_path",
    [
        pytest.param(path, id=path.stem)
        for path in ASSETS_PATH.iterdir()
        if path.stem != "__pycache__"
    ],
)
def test_plugin(plugin_manager, plugin_path):
    plugin_manager.import_path(plugin_path)

    assert sorted(plugin_manager.hook.hook_callback()) == ["It Works", "It Works Too"]
