import logging


class KVPairs:
    __slots__ = "kvpairs"

    def __init__(self, kwargs):
        self.kvpairs = kwargs

    def __str__(self):
        return " ".join(f"{k}={v}" for (k, v) in self.kvpairs.items())


class StructuredAdapter(logging.LoggerAdapter):
    def __init__(self, logger, extra=None):
        super().__init__(logger, extra or {})

    def log(self, level, msg, *, exc_info=None, stack_info=False, **params):
        if self.isEnabledFor(level):
            msg, kwargs = self.process(
                msg,
                dict(
                    exc_info=exc_info,
                    stack_info=stack_info,
                ),
            )
            kwargs["extra"]["params"] = KVPairs(params)
            verbosity = params.pop("_verbosity", 0)
            if verbosity == 2:
                level = 8
            elif verbosity == 3:
                level = 6
            self.logger.log(level, msg, **kwargs)

    def bind(self, **params):
        # TODO(vlaci)
        return self


import colorama

FG = colorama.Fore
BG = colorama.Back
S = colorama.Style

DEFAULT_COLORS = {
    "asctime": S.DIM,
    "levelname": "",
    "message": "",
    "name": S.BRIGHT,
    "params": S.NORMAL + FG.MAGENTA,
}

DEFAULT_LEVEL_COLORS = {
    logging.CRITICAL: FG.RED,
    logging.ERROR: FG.RED,
    logging.WARNING: FG.YELLOW,
    logging.INFO: FG.GREEN,
    logging.DEBUG: FG.RESET,
    logging.NOTSET: BG.RED,
}

DEFAULT_PARAM_COLORS = {
    "key": S.DIM + FG.MAGENTA,
    "value": FG.MAGENTA,
}


class Colorizer(logging.StrFormatStyle):
    def __init__(
        self,
        fmt,
        *,
        defaults,
        colors=DEFAULT_COLORS,
        level_colors=DEFAULT_LEVEL_COLORS,
        param_colors=DEFAULT_PARAM_COLORS,
    ) -> None:
        super().__init__(fmt, defaults=defaults)
        self._colors = colors
        self._level_colors = level_colors
        self._param_colors = param_colors

    def _format(self, record):
        if defaults := self._defaults:
            values = defaults | record.__dict__
        else:
            values = record.__dict__

        for key, style in self._colors.items():
            value = values[key]
            if key == "levelname":
                levelstyle = self._level_colors.get(
                    record.levelno
                ) or self._level_colors.get(logging.DEBUG)
                value = f"{levelstyle}{value}"
            elif isinstance(value, KVPairs):
                keystyle = self._param_colors["key"]
                valuestyle = self._param_colors["value"]
                value = " ".join(
                    (
                        f"{keystyle}{k}{S.RESET_ALL}: {valuestyle}{v}{S.RESET_ALL}"
                        for k, v in value.kvpairs.items()
                    )
                )
            values[key] = f"{style}{value}{S.RESET_ALL}"
        return self._fmt.format(**values)


class StructuredFormatter(logging.Formatter):
    def __init__(
        self,
        fmt,
        *args,
        defaults=None,
        colors=DEFAULT_COLORS,
        level_colors=DEFAULT_LEVEL_COLORS,
        param_colors=DEFAULT_PARAM_COLORS,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._colors = colors
        self._style = Colorizer(
            fmt,
            defaults=defaults,
            colors=colors,
            level_colors=level_colors,
            param_colors=param_colors,
        )

    def formatTime(self, record, datefmt) -> str:
        formatted = super().formatTime(record, datefmt)
        return f"{self._colors['asctime']}{formatted}{S.RESET_ALL}"

    def formatMessage(self, record) -> str:
        return super().formatMessage(record)
