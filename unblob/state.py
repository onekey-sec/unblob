from contextvars import ContextVar

exit_code_var: ContextVar[int] = ContextVar("exit_code_var")
