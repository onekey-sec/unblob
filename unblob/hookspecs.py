from typing import List, Type

import pluggy

from unblob.models import Handler

hookspec = pluggy.HookspecMarker("unblob")


@hookspec
def unblob_register_handlers() -> List[Type[Handler]]:
    """Register handler types to known handlers.

    :returns: The list of handlers to be registered
    """
    return []
