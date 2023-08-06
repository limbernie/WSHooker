"""instrument.py

Frida Instrumentation
"""
import frida
import json
import time

import config
import helpers

from printer import *

class Instrumenter:

  def __init__(self, hook):
    self.hook = hook
    self._device = frida.get_local_device()
    self._device.on("child-added", self.on_child_added)
    self._device.on("child-removed", self.on_child_removed)
    self._process_terminated = False

  def instrument(self,
    pid,
    debug=False,
    allow_bad_progid=False,
    allow_file=False,
    allow_net=False,
    allow_proc=False,
    allow_reg=False,
    allow_shell=False,
    allow_sleep=False,
    dynamic=False
  ):
    self.pid = pid
    session = frida.attach(self.pid)
    session.enable_child_gating()
    session.on("detached", self.on_detached)
    script = session.create_script(self.hook)
    script.on("message", self.on_message)
    script.on("destroyed", self.on_destroyed)
    script.load()

    # Sending config to script
    script.post({
      "type"             : "config",
      "debug"            : debug,
      "allow_bad_progid" : allow_bad_progid,
      "allow_file"       : allow_file,
      "allow_net"        : allow_net,
      "allow_proc"       : allow_proc,
      "allow_reg"        : allow_reg,
      "allow_shell"      : allow_shell,
      "allow_sleep"      : allow_sleep,
      "dynamic"          : dynamic,
      "bad_progids"      : json.dumps(config.bad_progids),
      "extension"        : config.extension,
      "filter"           : json.dumps(config.filter_from_tracing),
      "fixed_width"      : config.fixed_width,
      "work_dir"         : config.work_dir,
      "wshost"           : config.wsh_exe
    })

    # Keep the process suspended until resumed
    while True:
      try:
        time.sleep(0.5)
        if self._process_terminated:
          break
      except KeyboardInterrupt:
        status("Warning: Instrumentation script is destroyed")
        helpers.clean_up()
        break

    if not self._process_terminated:
      info("Killed process: %s" % self.pid)
      status("Exiting...")
      frida.kill(self.pid)

  def on_detached(self, message, data):
    helpers.clean_up()
    info("Killed process: %s" % self.pid)
    status("Exiting...")
    self._process_terminated = True

  def on_destroyed(self):
    status("Warning: Instrumentation script is destroyed")

  def on_message(self, message, data):
    if message["type"] == "send":
      msg_data = message["payload"]
      if msg_data["target"] == "registry":
        if msg_data["action"] == "delete":
          if msg_data["type"] == "key":
            if msg_data["path"] not in config.reg_keys_to_delete:
              config.reg_keys_to_delete.append(msg_data["path"])
          elif msg_data["type"] == "value":
            helpers.delete_reg_value(msg_data["path"])
        elif msg_data["action"] == "search":
          if msg_data["type"] == "value":
            helpers.print_inprocserver32_from_clsid(msg_data["clsid"])
      elif msg_data["target"] == "file":
        if msg_data["action"] == "delete":
          if msg_data["path"] not in config.files_to_delete:
            config.files_to_delete.append(msg_data["path"])
      elif msg_data["target"] == "folder":
        if msg_data["action"] == "delete":
          if msg_data["path"] not in config.folders_to_delete:
            config.folders_to_delete.append(msg_data["path"])
      elif msg_data["target"] == "frida":
        if msg_data["action"] == "resume":
          status("Windows Script Host PID: %s" % self.pid)
          frida.resume(self.pid)
          status("Ctrl-C to kill the process...")
          print("+---------+")
          print("|  Trace  |")
          print("+---------+")
      elif msg_data["target"] == "system":
        if msg_data["action"] == "log":
          try:
            msg_data["message"].encode("cp437") # Windows legacy code page
          except UnicodeEncodeError:
            pass
          else:
            log(msg_data["message"])
        elif msg_data["action"] == "decode":
          helpers.decode_powershell(msg_data["value"])

  def on_child_added(self, child):
    status("%s spawned child process: %s" % (self.pid, child.pid))
    frida.kill(child.pid)

  def on_child_removed(self, child):
    info("Killed child process: %s" % child.pid)
    log("|")

