"""printer.py

Various functions related to printing.
"""
import builtins
import random
import re
from time import perf_counter
import winreg

import config
from extras import BANNERS, BOLD, COLORS, RESET, UNDERLINE


def indent(message):
    """Indent message."""
    printf(f"{config.INDENT}{message}")


def printf(*objects, **kwargs):
    """Overload builtins.print() with `tee'-like feature and timestamp."""
    try:
        with open(f"{config.WORK_DIR}\\{config.TRACE}", "a", encoding="utf-8") as file:
            if config.TIMESTAMP:
                timestamp = f"[{perf_counter():10.3f}]"
                builtins.print(
                    config.SPACE.join([timestamp, strip(*objects)]), file=file, **kwargs
                )
                builtins.print(
                    config.SPACE.join([timestamp, *objects]), flush=True, **kwargs
                )
            else:
                builtins.print(
                    config.SPACE.join(["", strip(*objects)]), file=file, **kwargs
                )
                builtins.print(config.SPACE.join(["", *objects]), flush=True, **kwargs)
    except FileNotFoundError:
        builtins.print(*objects, **kwargs)


def status(message):
    """Marker: (**) status"""
    log(f"(**) {message}")


def info(message):
    """Marker: (II) informational"""
    log(f"(II) {message}")


def error(message):
    """Marker: (EE) error"""
    log(f"(EE) {message}")


def param(name, value):
    """Print parameter and its value."""
    log(f"|-- ({name.center(config.FIXED_WIDTH)}) => {value}")


def log(message):
    """Print message to console."""

    if message is None:
        return

    if config.FUN:
        if "|" in message:
            message = message.replace("|", highlight("|"))
            message = message.replace("--", highlight("--"))

    if re.match(r"^(\(\*\*\)|Call)", message):
        printf(message)
    else:
        indent(message)


def has_ansi_colors():
    """Check for ANSI colors support."""
    supported = False
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Console")
        data = winreg.QueryValueEx(key, "VirtualTerminalLevel")[0]
        if data == 1:
            supported = True
    except FileNotFoundError:
        pass
    return supported


def print_banner():
    """Print banner."""
    banner = random.choice(BANNERS)
    builtins.print(f"{bold(highlight(banner))}")


def print_trace_label(label="Trace"):
    """Print label with a border to indicate the start of a trace."""

    def border(label):
        return f"+-{'-' * len(label)}-+"

    border = border(label)

    printf(border)

    if config.FUN:
        label = "".join([highlight(char) for char in [*label]])

    printf(f"| {label} |")

    printf(border)


def bold(text):
    """Bolds text."""

    if has_ansi_colors():
        text = f"{BOLD}{text}{RESET}"

    return text


def highlight(text):
    """Highlights text with a random color."""

    color = random.choice(COLORS)

    if has_ansi_colors():
        text = f"{color}{text}{RESET}"

    return text


def underline(text):
    """Underlines text."""

    if has_ansi_colors():
        text = f"{UNDERLINE}{text}{RESET}"

    return text


def strip(text):
    """Strip ANSI escape sequences from text."""
    text = re.sub(r"\033\[\d+m", "", text)
    return text
