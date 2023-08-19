"""wshooker.py

WSHooker — Windows Script Hooking with Frida
"""

from os import makedirs
from os.path import abspath, basename, exists, splitext
import sys
from time import gmtime, strftime

import frida

import config
from helpers import remove_frida_temp_files, parse_arguments, post_actions
from instrumenter import Instrumenter
from printer import print_banner, printf


class WSHooker:
    """Class to represent WSHooker."""

    def __init__(self):
        self.configured = False
        self.parser, self.args = parse_arguments()
        self.script = None

    def configure(self):
        """Configure WSHooker."""

        # Reserved for future release.
        if self.args.pid is not None:
            self.parser.print_help()
            sys.exit(1)
        elif self.args.script:
            if exists(abspath(self.args.script)):
                self.script = abspath(self.args.script)
                filename, extension = splitext(basename(self.script))
                filename = filename.replace(" ", "_")
                if not extension:
                    print("Error: No file extension.")
                    sys.exit(1)
                elif extension not in config.VALID_EXTENSIONS:
                    print("Error: Invalid file extension.")
                    sys.exit(1)

                # Date and time expressed in ISO 8601 to prevent name collision.
                datetime = strftime("%Y%m%dT%H%M%SZ", gmtime())
                if self.args.dir:
                    workdir = f"{abspath(self.args.dir)}\\{datetime}_{filename}"
                else:
                    workdir = f"{abspath('.')}\\{config.TRACES}\\{datetime}_{filename}"
                makedirs(workdir)

                # Global configurations
                config.EXTENSION = extension
                config.FUN = self.args.fun
                config.TIMESTAMP = self.args.timestamp
                config.TRACE = self.args.trace
                config.WORK_DIR = workdir
                config.WSHOST = (
                    "cscript.exe" if not self.args.wscript else "wscript.exe"
                )

                self.configured = True
            else:
                print("Error: File not found.")
                sys.exit(1)
        else:
            self.parser.print_usage()
            sys.exit(1)

    def run(self):
        """Run WSHooker on script."""

        if not self.configured:
            print("Error: WSHooker is not configured.")
            sys.exit(1)

        remove_frida_temp_files()

        if not self.args.no_banner:
            print_banner()

        if exists(config.SYSWOW64):
            wshost = f"{config.SYSWOW64}\\{config.WSHOST}"
        else:
            wshost = f"{config.SYSTEM32}\\{config.WSHOST}"

        # Use "/b" to suppress alerts, errors or prompts
        cmd = [wshost, "/b", abspath(self.script)]

        # Arguments to malicious script, if any
        if self.args.args:
            for arg in self.args.args.split(" "):
                cmd.append(arg)

        with open("hook.js", "r", encoding="utf-8") as hook_js:
            hook = hook_js.read()

        # Hook options
        hook_options = {
            "debug": self.args.debug,
            "dynamic": self.args.dynamic,
            "allow_bad_progid": self.args.allow_bad_progid,
            "allow_file": self.args.allow_file,
            "allow_net": self.args.allow_net,
            "allow_proc": self.args.allow_proc,
            "allow_reg": self.args.allow_reg,
            "allow_shell": self.args.allow_shell,
            "allow_sleep": self.args.allow_sleep,
        }

        pid = frida.spawn(cmd)

        printf(f'Script: "{self.script}"')
        printf(f'Working directory: "{config.WORK_DIR}"')
        printf(f'Windows Script Host: "{wshost}"')
        printf(f"Windows Script Host process: {pid}")
        printf("Ctrl-C to stop the trace")
        printf("Markers: (**) status, (II) informational, (EE) error")

        instrumenter = Instrumenter(hook, pid)
        instrumenter.begin(options=hook_options)

        if instrumenter.process_terminated:
            post_actions(delay_in_sec=3)


if __name__ == "__main__":
    try:
        wshooker = WSHooker()
        wshooker.configure()
        wshooker.run()
    except KeyboardInterrupt:
        post_actions(delay_in_sec=3)
