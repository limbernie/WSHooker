"""printer.py

Various functions related to printing.
"""
import builtins
import random
import re
from time import perf_counter

from extras import BANNERS, COLORS, RESET
import config


def indent(message):
    """Indent message"""
    printf(f"{config.INDENT}{message}")


def printf(*objects, **kwargs):
    """Override builtins.print()"""
    try:
        with open(f"{config.WORK_DIR}\\{config.TRACE}", "a", encoding="utf-8") as file:
            if config.TIMESTAMP:
                timestamp = f"[{perf_counter():10.3f}]"
                builtins.print(
                    config.SPACE.join([timestamp, *objects]), file=file, **kwargs
                )
                builtins.print(
                    config.SPACE.join([timestamp, *objects]), flush=True, **kwargs
                )
            else:
                builtins.print(config.SPACE.join(["", *objects]), file=file, **kwargs)
                builtins.print(config.SPACE.join(["", *objects]), flush=True, **kwargs)
    except FileNotFoundError:
        builtins.print(*objects, **kwargs)


def status(message):
    """Debug: status"""
    log(f"(**) {message}")


def info(message):
    """Debug: info"""
    log(f"(II) {message}")


def error(message):
    """Debug: error"""
    log(f"(EE) {message}")


def param(name, value):
    """Print parameter"""
    log(f"|-- ({name.center(config.FIXED_WIDTH)}) => {value}")


def log(message):
    """Print message"""
    if message is None:
        return
    if re.match(r"^(\(\*\*\)|Call)", message):
        printf(message)
    else:
        indent(message)


def print_banner():
    """Print banner"""
    color = random.choice(COLORS)
    banner = random.choice(BANNERS)
    reset = RESET
    builtins.print(f"{color}{banner}{reset}")


def print_trace_label(label="Trace"):
    """Print label to indicate the start of a trace."""

    def border(label):
        printf(f"+-{'-' * len(label)}-+")

    border(label)
    printf(f"| {label} |")
    border(label)
