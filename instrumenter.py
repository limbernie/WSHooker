"""instrumenter.py

Frida Instrumentation
"""
from json import dumps
from time import gmtime, strftime, sleep

import frida

import config
from helpers import (
    decode_powershell,
    delete_reg_value,
    print_inprocserver32_from_clsid,
)
from printer import info, log, print_trace_label, status


class Instrumenter:
    """Instrumenter class to abstract Frida's instrumentation."""

    def __init__(self, hook, pid):
        self.hook = hook
        self.pid = pid
        self.device = frida.get_local_device()
        self.device.on("child-added", self.on_child_added)
        self.device.on("child-removed", self.on_child_removed)
        self.interrupted = False
        self.process_terminated = False
        self.defaults = {
            "debug": False,
            "dynamic": False,
            "allow_bad_progid": False,
            "allow_file": False,
            "allow_net": False,
            "allow_proc": False,
            "allow_reg_write": False,
            "allow_shell_exec": False,
            "allow_sleep": False,
        }

    def begin(self, options=None):
        """Begin instrumentation."""
        if options is None:
            options = self.defaults
        session = self.device.attach(self.pid)
        session.enable_child_gating()
        session.on("detached", self.on_detached)
        script = session.create_script(self.hook)
        script.on("message", self.on_message)
        script.on("destroyed", self.on_destroyed)
        script.load()

        # Sending settings to instrumentation script.
        script.post(
            {
                "type": "config",
                "debug": options["debug"],
                "dynamic": options["dynamic"],
                "allow_bad_progid": options["allow_bad_progid"],
                "allow_file": options["allow_file"],
                "allow_net": options["allow_net"],
                "allow_proc": options["allow_proc"],
                "allow_reg_write": options["allow_reg_write"],
                "allow_shell_exec": options["allow_shell_exec"],
                "allow_sleep": options["allow_sleep"],
                "bad_progids": dumps(config.BAD_PROGIDS),
                "extension": config.EXTENSION,
                "filter": dumps(config.FILTER),
                "fixed_width": config.FIXED_WIDTH,
                "work_dir": config.WORK_DIR,
                "wshost": config.WSHOST,
            }
        )

        # Keep the process suspended until resumed.
        while True:
            try:
                sleep(0.5)
                if self.process_terminated:
                    break
            except KeyboardInterrupt:
                status("Trace stopped because of Ctrl-C")
                self.interrupted = True
                break

        if not self.process_terminated:
            frida.kill(self.pid)
            raise KeyboardInterrupt

    def on_detached(self, message, data):
        """Called when process is detached."""
        if message == "process-terminated" and data is None:
            pass
        self.process_terminated = True

    def on_destroyed(self):
        """Called when instrumentation script is destroyed."""
        if not self.interrupted:
            status("Trace finished with no error")

    def on_message(self, message, data):
        """Called when message from instrumention script is posted."""
        if data is None:
            pass
        if message["type"] == "send":
            payload = message["payload"]
            self.on_action(payload.get("action"), payload.get("parameter"))

    def on_child_added(self, child):
        """Called when child process is added."""
        status(f"{self.pid} spawned child process: {child.pid}")
        frida.kill(child.pid)

    def on_child_removed(self, child):
        """Called when child process is removed."""
        info(f"Killed child process: {child.pid}")
        log("|")

    def on_action(self, action, parameter):
        """Invoke helper functions to complete action, except for resume."""
        if action == "resume":
            self.resume()
        elif parameter is not None:
            try:
                # Windows legacy console code page
                parameter.encode("cp437")
            except UnicodeEncodeError:
                parameter = None
            actions = {
                "decode_powershell": decode_powershell,
                "delete_file": config.FILES_TO_DELETE.append,
                "delete_folder": config.FOLDERS_TO_DELETE.append,
                "delete_reg_key": config.REG_KEYS_TO_DELETE.append,
                "delete_reg_value": delete_reg_value,
                "log": log,
                "print_inprocserver32_from_clsid": print_inprocserver32_from_clsid,
            }
            actions.get(action)(parameter)

    def resume(self):
        """Resume Frida instrumentation."""
        frida.resume(self.pid)
        start = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
        config.JSON_OUTPUT["start"] = start
        print_trace_label(f'Trace started on {start}')
