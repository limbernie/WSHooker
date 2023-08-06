"""wshooker.py

Windows Script Hooking with Frida
"""
import argparse
import os
import time

import frida

import config
import helpers

from instrument import Instrumenter
from printer import *

if __name__ == "__main__":
  helpers.clean_frida_temp_files()
  parser = argparse.ArgumentParser(description="WSHooker - Windows Script Hooking with Frida")
  group = parser.add_mutually_exclusive_group()
  group.add_argument(
    "-p",
    "--pid",
    dest="pid",
    help="process id (reserved for future release)",
    type=int
  )
  group.add_argument(
    "-s",
    "--script",
    dest="script",
    help="path to malicious script"
  )
  parser.add_argument(
    "-a",
    "--args",
    dest="args",
    help="arguments to malicious script, e.g., -a \"arg1 arg2 arg3 ...\""
  )
  parser.add_argument(
    "-o",
    "--output",
    dest="trace",
    default="trace.log",
    help="write output trace to file (default is trace.log)"
  )
  parser.add_argument(
    "--allow-bad-progid",
    dest="allow_bad_progid",
    action="store_true",
    help="(dangerous) allow known bad ProgID"
  )
  parser.add_argument(
    "--allow-file",
    dest="allow_file",
    action="store_true",
    help="(dangerous) allow file copy/move/write"
  )
  parser.add_argument(
    "--allow-net",
    dest="allow_net",
    action="store_true",
    help="(dangerous) allow network requests"
  )
  parser.add_argument(
    "--allow-proc",
    dest="allow_proc",
    action="store_true",
    help="(dangerous) allow Win32_Process"
  )
  parser.add_argument(
    "--allow-reg",
    dest="allow_reg",
    action="store_true",
    help="(dangerous) allow registry write"
  )
  parser.add_argument(
    "--allow-shell",
    dest="allow_shell",
    action="store_true",
    help="(dangerous) allow shell command to run as Administrator"
  )
  parser.add_argument(
    "--allow-sleep",
    dest="allow_sleep",
    action="store_true",
    help="(slow-down) allow WScript.Sleep()"
  )
  parser.add_argument(
    "--debug",
    dest="debug",
    action="store_true",
    help="(verbose) display debug message"
  )
  parser.add_argument(
    "--dynamic",
    dest="dynamic",
    action="store_true",
    help="(verbose) enable dynamic tracing"
  )
  parser.add_argument(
    "--no-banner",
    dest="no_banner",
    action="store_true",
    help="remove banner in output trace"
  )
  parser.add_argument(
    "--timestamp",
    dest="timestamp",
    action="store_true",
    help="display timestamp in output trace"
  )
  parser.add_argument(
    "--wscript",
    dest="wscript",
    action="store_true",
    help="switch to wscript.exe (default is cscript.exe)"
  )
  args = parser.parse_args()

  with open("hook.js", 'r') as fd:
    hook = fd.read()

  instrumenter = Instrumenter(hook)

  # Reserved for future release
  if args.pid is not None:
    parser.print_help()
    exit(1)

  elif args.script:
    if os.path.exists(args.script):
      valid_extensions = ["js", "vbs", "wsf"]
      try:
        file_name = os.path.basename(args.script).rsplit('.', 1)[0]
        extension = os.path.basename(args.script).rsplit('.', 1)[1]
        if extension.lower() not in valid_extensions:
          print("Error: Invalid file extension")
          exit(1)
      except IndexError:
          print("Error: No file extension")
          exit(1)

      if args.wscript:
        config.wsh_exe = "wscript.exe"

      if not args.no_banner:
        helpers.print_banner()
      
      # Prepend date and time expressed in ISO 8601 to script's file name sans extension.
      date_time = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
      work_dir  = ''.join(['.\\', config.traces, '\\', date_time, '_', file_name])
      
      os.makedirs(work_dir)

      config.extension = extension
      config.timestamp = args.timestamp
      config.trace     = args.trace
      config.work_dir  = work_dir

      status("Script: \"%s\"" % os.path.abspath(args.script))
      
      status("Working Directory: \"%s\"" % work_dir)

      if os.path.exists(config.wsh_path_wow64):
        wshost = ''.join([config.wsh_path_wow64, config.wsh_exe])
      else:
        wshost = ''.join([config.wsh_path, config.wsh_exe])

      status("Windows Script Host: \"%s\"" % wshost)

      # Use "/b" to suppress alerts, errors or prompts
      cmd = [wshost, "/b", args.script]

      # Arguments to malicious script, if any
      if args.args:
        [cmd.append(a) for a in args.args.split(' ')]

      pid = frida.spawn(cmd)

      instrumenter.instrument(
        pid,
        args.debug,
        args.allow_bad_progid,
        args.allow_file,
        args.allow_net,
        args.allow_proc,
        args.allow_reg,
        args.allow_shell,
        args.allow_sleep,
        args.dynamic
     )
    else:
      print("Error: File not found")
      exit(1)
  else:
    parser.print_usage()
    exit(1)
