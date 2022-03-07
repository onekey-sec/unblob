from unblob.plugins import hookimpl


@hookimpl
def hook_callback():
    return "It Works"


@hookimpl(specname="hook_callback")
def second_implementation():
    return "It Works Too"
