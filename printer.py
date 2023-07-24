import builtins
import config
import re
import time

def indent(message):
  print(''.join([config.INDENT, message]))

def print(*objects, **kwargs):
  try:
    with open(''.join(['.\\', config.WORK_DIR, '\\', config.TRACE]), 'a') as f:
      if config.TIMESTAMP:
        timestamp = "[%10.3f]" % time.perf_counter()
        builtins.print(config.SPACE.join([timestamp, *objects]), file=f, **kwargs)
        builtins.print(config.SPACE.join([timestamp, *objects]), flush=True, **kwargs)
      else:
        builtins.print(config.SPACE.join(['', *objects]), file=f, **kwargs)
        builtins.print(config.SPACE.join(['', *objects]), flush=True, **kwargs)
  except FileNotFoundError:
    builtins.print(*objects, **kwargs)
  except UnicodeEncodeError:
    pass

def status(message):
  log(''.join(["[*]", ' ', message]))
  
def info(message):
  log(''.join(["[+]", ' ', message]))
  
def error(message):
  log(''.join(["[-]", ' ', message]))
  
def param(name, value):
  log(''.join(["|--", ' ', name, " => ", value]))
  
def log(message):
  if re.match(r"^(\[\*\]|Call)", message):
    print(message)
  else:
    indent(message)