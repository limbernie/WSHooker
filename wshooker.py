import argparse
import frida
import os
import time

import config
import helpers

from instrument import Instrumenter

def print(*objects, **kwargs):
  helpers.print(*objects, **kwargs)

if __name__ == '__main__':
  helpers.clean_frida_helper()
  parser = argparse.ArgumentParser(description='WSHooker - Windows Script Hooking with Frida')
  group = parser.add_mutually_exclusive_group()
  group.add_argument(
    '-p',
    '--pid',
    dest="pid",
    help="process id (reserved for future release)",
    type=int
  )
  group.add_argument(
    '-s',
    '--script',
    dest="script",
    help="path to malicious script"
  )
  parser.add_argument(
    '-a',
    '--args',
    dest='args',
    help="arguments to malicious script, e.g., -a \"arg1 arg2 arg3 ...\""
  )
  parser.add_argument(
    '-o',
    '--output',
    dest='trace',
    default="trace.log",
    help="write output trace to file (defaults to trace.log)"
  )
  parser.add_argument(
    '--allow-badcom',
    dest="allow_badcom",
    action="store_true",
    help="(dangerous) allow bad COM"
  )
  parser.add_argument(
    '--allow-file',
    dest="allow_file",
    action="store_true",
    help="(dangerous) allow file copy/move/write"
  )
  parser.add_argument(
    '--allow-net',
    dest="allow_net",
    action="store_true",
    help="(dangerous) allow network requests"
  )
  parser.add_argument(
    '--allow-proc',
    dest="allow_proc",
    action="store_true",
    help="(dangerous) allow Win32_Process"
  )
  parser.add_argument(
    '--allow-reg',
    dest="allow_reg",
    action="store_true",
    help="(dangerous) allow registry write"
  )
  parser.add_argument(
    '--allow-shell',
    dest="allow_shell",
    action="store_true",
    help="(dangerous) allow shell commands as Administrator"
  )
  parser.add_argument(
    '--allow-sleep',
    dest="allow_sleep",
    action="store_true",
    help="(slow-down) allow WScript.Sleep()"
  )
  parser.add_argument(
    '--debug',
    dest="debug",
    action="store_true",
    help="(verbose) display debug message"
  )
  parser.add_argument(
    '--dynamic',
    dest="dynamic",
    action="store_true",
    help="(verbose) enable dynamic tracing"
  )
  parser.add_argument(
    '--no-banner',
    dest="no_banner",
    action="store_true",
    help="remove banner in output trace"
  )
  parser.add_argument(
    '--timestamp',
    dest="timestamp",
    action="store_true",
    help="enable timestamp in output trace"
  )
  args = parser.parse_args()

  with open('hook.js', 'r') as fd:
    hook = fd.read()

  instrumenter = Instrumenter(hook)

  # reserved for future release
  if args.pid is not None:
    parser.print_help()
    exit(1)

  elif args.script:
    if os.path.exists(args.script):
      valid_extensions = ['js', 'vbs', 'wsf']
      try:
        EXTENSION = os.path.basename(args.script).rsplit('.', 1)[1]
      except:
        pass
      if EXTENSION.lower() not in valid_extensions:
        print(" [!] Error: Invalid extension or no extension")
        exit(1)

      if not args.no_banner:
        helpers.print_banner()

      ISO_8601 = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
      WORK_DIR = config.TRACES + "\\" + ISO_8601 + '_' + os.path.basename(args.script).rsplit('.', 1)[0]
      try:
        os.makedirs(WORK_DIR)
        print(' [*] Working directory: %s' % WORK_DIR)
      except FileExistsError:
        print(' [*] Working directory already exists: %s' % WORK_DIR)

      config.EXTENSION = EXTENSION
      config.TIMESTAMP = args.timestamp
      config.TRACE     = args.trace
      config.WORK_DIR  = WORK_DIR

      if os.path.exists(Instrumenter._WSCRIPT_PATH_WOW64):
        print(' [*] x64 detected...using SysWOW64')
        wshost = Instrumenter._WSCRIPT_PATH_WOW64 + Instrumenter._WSCRIPT_EXE
      else:
        print(' [*] Using System32')
        wshost = Instrumenter._WSCRIPT_PATH + Instrumenter._WSCRIPT_EXE

      # use '/b' to suppress alerts, errors or prompts
      cmd = [wshost, '/b', args.script]

      # arguments to malicious script, if any
      if args.args:
        for a in args.args.split(' '):
          cmd.append(a)

      pid = frida.spawn(cmd)

      instrumenter.instrument(
        pid,
        args.debug,
        args.allow_badcom,
        args.allow_file,
        args.allow_net,
        args.allow_proc,
        args.allow_reg,
        args.allow_shell,
        args.allow_sleep,
        args.dynamic
     )
    else:
      print(" [!] Error: No such file")
      exit(1)
  else:
    parser.print_usage()
    exit(1)
