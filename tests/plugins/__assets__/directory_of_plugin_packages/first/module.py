from unblob.plugins import hookimpl


@hookimpl
def hook_callback():
    return "It Works"
