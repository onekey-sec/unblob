import os
from threading import Lock

__last_id = 0
__last_id_lock = Lock()


def new_id():
    # NOTE, that uuid4 can not be used, as there are multiple processes at run time,
    # and as subprocesses inherit the random number state, so uuid4 would generate colliding ids
    # another option that would not work is to use uuid1, but we could generate the id
    # at the same time

    global __last_id  # noqa: PLW0603
    with __last_id_lock:
        __last_id += 1
        return f"{os.getpid()}:{__last_id}"
