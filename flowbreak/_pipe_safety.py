"""Shared helper so every CLI entrypoint exits cleanly when its output is
piped into something that closes early (e.g. `| head`), instead of printing
a BrokenPipeError traceback - a very normal thing for a user to do with a
CLI tool's output."""

import os
import sys


def run_main_safely(main_func) -> int:
    try:
        return main_func()
    except BrokenPipeError:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        return 1
