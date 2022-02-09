import functools
import signal

from structlog import get_logger

logger = get_logger()


class ShutDownRequired(BaseException):
    def __init__(self, signal: str):
        super().__init__()
        self.signal = signal


def terminate_gracefully(func):
    @functools.wraps(func)
    def decorator(*args, **kwargs):
        signals_fired = []

        def _handle_signal(signum: int, frame):
            nonlocal signals_fired
            signals_fired.append((signum, frame))
            raise ShutDownRequired(signal=signal.Signals(signum).name)

        original_signal_handlers = {
            signal.SIGINT: signal.signal(signal.SIGINT, _handle_signal),
            signal.SIGTERM: signal.signal(signal.SIGTERM, _handle_signal),
        }

        logger.debug(
            "Setting up signal handlers",
            original_signal_handlers=original_signal_handlers,
            _verbosity=2,
        )

        try:
            return func(*args, **kwargs)
        except ShutDownRequired as exc:
            logger.warning("Shutting down", signal=exc.signal)
        finally:
            # Set back the original signal handlers
            for sig, handler in original_signal_handlers.items():
                signal.signal(sig, handler)

            # Call the original signal handler with the fired and catched signal(s)
            for sig, frame in signals_fired:
                handler = original_signal_handlers.get(sig)
                if callable(handler):
                    handler(sig, frame)

    return decorator
