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
    allow_badcom=False,
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
      "type" : "config",
      "debug" : debug,
      "allow_badcom"  : allow_badcom,
      "allow_file"    : allow_file,
      "allow_net"     : allow_net,
      "allow_proc"    : allow_proc,
      "allow_reg"     : allow_reg,
      "allow_shell"   : allow_shell,
      "allow_sleep"   : allow_sleep,
      "dynamic"       : dynamic,
      "badprogid"     : json.dumps(config.BADPROGID),
      "extension"     : config.EXTENSION,
      "filter"        : json.dumps(config.FILTER),
      "work_dir"      : config.WORK_DIR
    })

    # Keep the process suspended until resumed
    while True:
      try:
        time.sleep(0.5)
        if self._process_terminated:
          break
      except KeyboardInterrupt:
        status("Warning: Instrumentation script is destroyed")
        helpers.cleanup()
        break

    if not self._process_terminated:
      info("Killed process: %s" % self.pid)
      status("Exiting...")
      frida.kill(self.pid)

  def on_detached(self, message, data):
    helpers.cleanup()
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
            if msg_data["path"] not in config.REG_KEYS:
              config.REG_KEYS.append(msg_data["path"])
          elif msg_data["type"] == "value":
            helpers.deleteValue(msg_data["path"])
        elif msg_data["action"] == "search":
          if msg_data["type"] == "value":
            helpers.InprocServer32FromCLSID(msg_data["clsid"])
      elif msg_data["target"] == "file":
        if msg_data["action"] == "delete":
          if msg_data["path"] not in config.FILES:
            config.FILES.append(msg_data["path"])
      elif msg_data["target"] == "folder":
        if msg_data["action"] == "delete":
          if msg_data["path"] not in config.FOLDERS:
            config.FOLDERS.append(msg_data["path"])
      elif msg_data["target"] == "frida":
        if msg_data["action"] == "resume":
          status("Hooking process: %s" % self.pid)
          frida.resume(self.pid)
          status("[*] Press Ctrl-C to kill the process...")
          print("+---------+")
          print("|  Trace  |")
          print("+---------+")
      elif msg_data["target"] == "system":
        if msg_data["action"] == "log":
          log(msg_data["message"])
        elif msg_data["action"] == "decode":
          helpers.decodePowerShell(msg_data["value"])

  def on_child_added(self, child):
    status("%s spawned child process: %s" % (self.pid, child.pid))
    frida.kill(child.pid)

  def on_child_removed(self, child):
    info("Killed child process: %s" % child.pid)
    log("|")

