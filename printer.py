import builtins
import re
import time

import config

def indent(message):
  print(''.join([config.INDENT, message]))

def print(*objects, **kwargs):
  try:
    with open(''.join([config.WORK_DIR, '\\', config.TRACE]), 'a') as f:
      if config.TIMESTAMP:
        timestamp = "[%10.3f]" % time.perf_counter()
        builtins.print(config.SPACE.join([timestamp, *objects]), file=f, **kwargs)
        builtins.print(config.SPACE.join([timestamp, *objects]), flush=True, **kwargs)
      else:
        builtins.print(config.SPACE.join(['', *objects]), file=f, **kwargs)
        builtins.print(config.SPACE.join(['', *objects]), flush=True, **kwargs)
  except FileNotFoundError:
    builtins.print(*objects, **kwargs)

def status(message):
  log(''.join(["[*]", ' ', message]))
  
def info(message):
  log(''.join(["[+]", ' ', message]))
  
def error(message):
  log(''.join(["[-]", ' ', message]))
  
def param(name, value):
  log(''.join(["|--", ' ', '(', name.center(config.FIXED_WIDTH), ')', " => ", value]))
  
def log(message):
  if re.match(r"^(\[\*\]|Call)", message):
    print(message)
  else:
    indent(message)