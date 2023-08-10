"""instrumenter.py

Frida Instrumentation
"""
from json import dumps
from time import sleep

import frida

import config
from helpers import (
    clean_up,
    decode_powershell,
    delete_reg_value,
    print_inprocserver32_from_clsid,
)
from printer import info, log, printf, status


class Instrumenter:
    """Instrumenter class to abstract Frida's instrumentation."""

    def __init__(self, hook, pid):
        self.hook = hook
        self.pid = pid
        self._device = frida.get_local_device()
        self._device.on("child-added", self.on_child_added)
        self._device.on("child-removed", self.on_child_removed)
        self._process_terminated = False
        self.defaults = {
            "debug": False,
            "dynamic": False,
            "allow_bad_progid": False,
            "allow_file": False,
            "allow_net": False,
            "allow_proc": False,
            "allow_reg": False,
            "allow_shell": False,
            "allow_sleep": False,
        }

    def instrument(self, options=None):
        """Begin instrumentation"""
        if options is None:
            options = self.defaults
        session = frida.attach(self.pid)
        session.enable_child_gating()
        session.on("detached", self.on_detached)
        script = session.create_script(self.hook)
        script.on("message", self.on_message)
        script.on("destroyed", self.on_destroyed)
        script.load()

        # Sending config to instrumentation script
        script.post(
            {
                "type": "config",
                "debug": options["debug"],
                "dynamic": options["dynamic"],
                "allow_bad_progid": options["allow_bad_progid"],
                "allow_file": options["allow_file"],
                "allow_net": options["allow_net"],
                "allow_proc": options["allow_proc"],
                "allow_reg": options["allow_reg"],
                "allow_shell": options["allow_shell"],
                "allow_sleep": options["allow_sleep"],
                "bad_progids": dumps(config.BAD_PROGIDS),
                "extension": config.EXTENSION,
                "filter": dumps(config.FILTER_FROM_TRACING),
                "fixed_width": config.FIXED_WIDTH,
                "work_dir": config.WORK_DIR,
                "wshost": config.WSH_EXE,
            }
        )

        # Keep the process suspended until resumed
        while True:
            try:
                sleep(0.5)
                if self._process_terminated:
                    break
            except KeyboardInterrupt:
                status("Warning: Instrumentation script is destroyed")
                clean_up()
                break

        if not self._process_terminated:
            info(f"Killed process: {self.pid}")
            status("Exiting...")
            frida.kill(self.pid)

    def on_detached(self, message, data):
        """Called when process is detached."""
        if message == "process-terminated" and data is None:
            pass
        clean_up()
        info(f"Killed process: {self.pid}")
        status("Exiting...")
        self._process_terminated = True

    def on_destroyed(self):
        """Called when instrumentation script is destroyed."""
        status("Warning: Instrumentation script is destroyed")

    def on_message(self, message, data):
        """Called when message from instrumention script is posted."""
        if data is None:
            pass
        if message["type"] == "send":
            payload = message["payload"]
            self.do_action(payload.get("action"), payload.get("parameter"))

    def on_child_added(self, child):
        """Called when child process is added."""
        status(f"{self.pid} spawned child process: {child.pid}")
        frida.kill(child.pid)

    def on_child_removed(self, child):
        """Called when child process is removed."""
        info(f"Killed child process: {child.pid}")
        log("|")

    def do_action(self, action, parameter):
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
        status(f"Windows Script Host PID: {self.pid}")
        frida.resume(self.pid)
        status("Ctrl-C to kill the process...")
        printf("+---------+")
        printf("|  Trace  |")
        printf("+---------+")
