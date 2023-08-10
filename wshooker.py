"""wshooker.py

Windows Script Hooking with Frida
"""
from argparse import ArgumentParser
from os import makedirs
from os.path import abspath, basename, exists, splitext
import sys
from time import gmtime, strftime

import frida

import config
from helpers import clean_frida_temp_files
from instrumenter import Instrumenter
from printer import print_banner, status

if __name__ == "__main__":
    clean_frida_temp_files()
    parser = ArgumentParser(description="WSHooker - Windows Script Hooking with Frida")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-p",
        "--pid",
        dest="pid",
        help="process id (reserved for future release)",
        type=int,
    )
    group.add_argument("-s", "--script", dest="script", help="path to malicious script")
    parser.add_argument(
        "-a",
        "--args",
        dest="args",
        help='arguments to malicious script, e.g., -a "arg1 arg2 arg3 ..."',
    )
    parser.add_argument(
        "-d", "--directory", dest="dir", help="directory or folder to hold output trace"
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="trace",
        default="trace.log",
        help="write output trace to file (default is trace.log)",
    )
    parser.add_argument(
        "--allow-bad-progid",
        dest="allow_bad_progid",
        action="store_true",
        help="(dangerous) allow known bad ProgID",
    )
    parser.add_argument(
        "--allow-file",
        dest="allow_file",
        action="store_true",
        help="(dangerous) allow file copy/move/write",
    )
    parser.add_argument(
        "--allow-net",
        dest="allow_net",
        action="store_true",
        help="(dangerous) allow network requests",
    )
    parser.add_argument(
        "--allow-proc",
        dest="allow_proc",
        action="store_true",
        help="(dangerous) allow Win32_Process",
    )
    parser.add_argument(
        "--allow-reg",
        dest="allow_reg",
        action="store_true",
        help="(dangerous) allow registry write",
    )
    parser.add_argument(
        "--allow-shell",
        dest="allow_shell",
        action="store_true",
        help="(dangerous) allow shell command to run as Administrator",
    )
    parser.add_argument(
        "--allow-sleep",
        dest="allow_sleep",
        action="store_true",
        help="(slow-down) allow WScript.Sleep()",
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        help="(verbose) display debug message",
    )
    parser.add_argument(
        "--dynamic",
        dest="dynamic",
        action="store_true",
        help="(verbose) enable dynamic tracing",
    )
    parser.add_argument(
        "--no-banner",
        dest="no_banner",
        action="store_true",
        help="remove banner in output trace",
    )
    parser.add_argument(
        "--timestamp",
        dest="timestamp",
        action="store_true",
        help="display timestamp in output trace",
    )
    parser.add_argument(
        "--wscript",
        dest="wscript",
        action="store_true",
        help="switch to wscript.exe (default is cscript.exe)",
    )
    args = parser.parse_args()

    # Reserved for future release.
    if args.pid is not None:
        parser.print_help()
        sys.exit(1)
    elif args.script:
        if exists(args.script):
            file_name, extension = splitext(basename(args.script))
            file_name = file_name.replace(" ", "_")
            if not extension:
                print("Error: No file extension")
                sys.exit(1)
            elif extension.lower() not in config.VALID_EXTENSIONS:
                print("Error: Invalid file extension")
                sys.exit(1)

            if not args.no_banner:
                print_banner()

            # Prepend date and time expressed as ISO 8601 to script's file name
            # sans extension so that there's no chance of name collision.
            date_time = strftime("%Y%m%dT%H%M%SZ", gmtime())

            if args.dir:
                WORK_DIR = "".join([abspath(args.dir), "\\", date_time, "_", file_name])
            else:
                WORK_DIR = "".join(
                    [abspath("."), "\\", config.TRACES, "\\", date_time, "_", file_name]
                )

            makedirs(WORK_DIR)

            # Global configurations
            config.EXTENSION = extension
            config.TIMESTAMP = args.timestamp
            config.TRACE = args.trace
            config.WORK_DIR = WORK_DIR
            config.WSH_EXE = "wscript.exe" if args.wscript else "cscript.exe"

            status(f'Script: "{abspath(args.script)}"')

            status(f'Working Directory: "{WORK_DIR}"')

            if exists(config.WSH_PATH_WOW64):
                WSHOST = "".join([config.WSH_PATH_WOW64, config.WSH_EXE])
            else:
                WSHOST = "".join([config.WSH_PATH, config.WSH_EXE])

            status(f'Windows Script Host: "{WSHOST}"')

            # Use "/b" to suppress alerts, errors or prompts
            cmd = [WSHOST, "/b", args.script]

            # Arguments to malicious script, if any
            if args.args:
                for a in args.args.split(" "):
                    cmd.append(a)

            pid = frida.spawn(cmd)

            with open("hook.js", "r", encoding="utf-8") as hook_js:
                hook = hook_js.read()

            instrumenter = Instrumenter(hook, pid)

            # Hook options
            hook_options = {
                "debug": args.debug,
                "dynamic": args.dynamic,
                "allow_bad_progid": args.allow_bad_progid,
                "allow_file": args.allow_file,
                "allow_net": args.allow_net,
                "allow_proc": args.allow_proc,
                "allow_reg": args.allow_reg,
                "allow_shell": args.allow_shell,
                "allow_sleep": args.allow_sleep,
            }

            instrumenter.instrument(options=hook_options)
        else:
            print("Error: File not found")
            sys.exit(1)
    else:
        parser.print_usage()
        sys.exit(1)
