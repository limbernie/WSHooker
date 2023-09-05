"""printer.py

Various functions related to printing.
"""
import builtins
from random import choice
import re
from time import perf_counter
import winreg

import config
from extras import (
    BANNERS,
    BOLD,
    BACKGROUND,
    BLACK_OR_WHITE,
    FOREGROUND,
    PERLISISMS,
    RESET,
    UNDERLINE,
)


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
    """Print message based on its content to console."""

    def split_call(message):
        """Split call into image and symbol."""
        match = re.match(r"Call: (.*)!(.*)\(\)", message)
        if match is not None:
            image, symbol = match.groups()
        return (image.strip(), symbol.strip())

    def split_param(message):
        "Split parameter into name and value."
        match = re.match(r"\s*\|-- \(\s*(.*)\s*\) => (.*)", message)
        if match is not None:
            name, value = match.groups()
        return (name.strip(), value.strip())

    if message is None:
        return

    if "Call:" in message:
        image, symbol = split_call(message)
        call = {"image": image, "symbol": symbol, "params": {}}
        config.JSON_OUTPUT["trace"].append(call)
    elif "|--" in message:
        name, value = split_param(message)
        match = re.match(r"^\d+$", value)
        if match is not None:
            value = int(value)
        if "Action" in name or "Access" in name:
            config.JSON_OUTPUT["trace"][-1][name.lower()] = value.lower()
        else:
            params = config.JSON_OUTPUT["trace"][-1]["params"]
            params[name.lower()] = value

    if config.FUN:
        if "|" in message:
            message = message.replace("|", fun("|"))
            message = message.replace("--", fun("--"))

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
    """Print WSHooker banner."""

    banner = choice(BANNERS)

    if config.FUN:
        builtins.print(f"{fun(banner)}")
    else:
        builtins.print(f"{highlight(banner)}")


def print_trace_label(label="Trace"):
    """Print label with a border to indicate the start of a trace."""

    def border(label):
        return f"+-{'-' * len(label)}-+"

    border = border(label)

    printf(border)

    if config.FUN:
        label = ransomize(label)

    printf(f"| {label} |")

    printf(border)


def bold(text):
    """Bolds text."""

    if config.ANSI_COLORS:
        text = f"{BOLD}{text}{RESET}"

    return text


def fun(text):
    """Rainbow text."""

    if config.ANSI_COLORS:
        text = "".join([f"{choice(FOREGROUND)}{x}{RESET}" for x in [*text]])

    return text


def ransomize(text):
    """Ransomize text like those found in ransom notes."""

    def _ransomize(text):
        if config.ANSI_COLORS:
            text = "".join(
                [f"{choice(BACKGROUND)}{BLACK_OR_WHITE[1]}{x}{RESET}" for x in [*text]]
            )

        return text

    return " ".join([_ransomize(word) for word in text.split(" ")])


def epigram():
    """Return a random Perlisism."""
    return choice(PERLISISMS)


def highlight(text):
    """Highlights text with a random foreground color."""

    if config.ANSI_COLORS:
        text = f"{choice(FOREGROUND)}{text}{RESET}"

    return text


def underline(text):
    """Underlines text."""

    if config.ANSI_COLORS:
        text = f"{UNDERLINE}{text}{RESET}"

    return text


def strip(text):
    """Strip ANSI escape sequences from text."""
    text = re.sub(r"\033\[\d+m", "", text)
    return text
