"""printer.py

Various functions related to printing.
"""
import builtins
import random
import re
import time

import extras
import config

def indent(message):
  print(''.join([config.indent, message]))

def print(*objects, **kwargs):
  try:
    with open(''.join([config.work_dir, '\\', config.trace]), 'a') as f:
      if config.timestamp:
        timestamp = "[%10.3f]" % time.perf_counter()
        builtins.print(config.space.join([timestamp, *objects]), file=f, **kwargs)
        builtins.print(config.space.join([timestamp, *objects]), flush=True, **kwargs)
      else:
        builtins.print(config.space.join(['', *objects]), file=f, **kwargs)
        builtins.print(config.space.join(['', *objects]), flush=True, **kwargs)
  except FileNotFoundError:
    builtins.print(*objects, **kwargs)

def status(message):
  log(''.join(["[*]", ' ', message]))
  
def info(message):
  log(''.join(["[+]", ' ', message]))
  
def error(message):
  log(''.join(["[-]", ' ', message]))
  
def param(name, value):
  log(''.join(["|--", ' ', '(', name.center(config.fixed_width), ')', " => ", value]))
  
def log(message):
  if re.match(r"^(\[\*\]|Call)", message):
    print(message)
  else:
    indent(message)
    
def print_banner():
  builtins.print("%s%s%s" % (
    random.choice(extras.colors), 
    random.choice(extras.banners),
    extras.reset
  ))