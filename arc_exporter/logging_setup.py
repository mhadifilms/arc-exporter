"""Centralised logging setup so the CLI and library agree on format and verbosity."""

from __future__ import annotations

import logging
import sys
from typing import TextIO

from rich.console import Console
from rich.logging import RichHandler

_console: Console | None = None
_err_console: Console | None = None


def console(stderr: bool = False) -> Console:
    """Return a singleton :class:`rich.console.Console`.

    Using one console per stream lets us route progress + summary tables to stdout while
    keeping diagnostic logs on stderr — important for CLI piping.
    """
    global _console, _err_console
    if stderr:
        if _err_console is None:
            _err_console = Console(stderr=True, soft_wrap=False, highlight=False)
        return _err_console
    if _console is None:
        _console = Console(soft_wrap=False, highlight=False)
    return _console


def setup_logging(verbosity: int = 0, *, json_logs: bool = False) -> logging.Logger:
    """Configure the root logger.

    Parameters
    ----------
    verbosity
        ``0`` = WARNING, ``1`` = INFO, ``2+`` = DEBUG.
    json_logs
        If ``True`` emit plain JSON-ish lines to stderr (useful for scripting); otherwise
        use the colourised :class:`rich.logging.RichHandler`.
    """
    level = {0: logging.WARNING, 1: logging.INFO}.get(verbosity, logging.DEBUG)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    handler: logging.Handler
    if json_logs:
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                fmt='{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":%(message)r,"name":"%(name)s"}',
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )
    else:
        handler = RichHandler(
            console=console(stderr=True),
            show_time=verbosity >= 2,
            show_path=verbosity >= 2,
            rich_tracebacks=True,
            markup=False,
        )
    root.addHandler(handler)

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING if verbosity < 2 else logging.INFO)

    return logging.getLogger("arc_exporter")


def stream_for_progress() -> TextIO:
    """Where ``rich.progress`` should render. Stderr keeps stdout clean for JSON output."""
    return sys.stderr
