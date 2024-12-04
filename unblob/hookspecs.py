import pluggy

from unblob.models import DirectoryHandler, Handler

hookspec = pluggy.HookspecMarker("unblob")


@hookspec
def unblob_register_handlers() -> list[type[Handler]]:
    """Register handler types to known handlers.

    :returns: The list of handlers to be registered
    """
    return []


@hookspec
def unblob_register_dir_handlers() -> list[type[DirectoryHandler]]:
    """Register directory handler types to known handlers.

    :returns: The list of directory handlers to be registered
    """
    return []
