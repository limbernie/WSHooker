import base64
import builtins
import glob
import os
import random
import re
import shutil
import time
import winreg

import config
import extras

def print(*objects, **kwargs):
  try:
    with open('.\\' + config.WORK_DIR + '\\' + config.TRACE, 'a') as f:
      if config.TIMESTAMP:
        timestamp = "%09.3fs" % time.perf_counter()
        builtins.print(' '.join([timestamp, *objects]), file=f, **kwargs)
        builtins.print(' '.join([timestamp, *objects]), flush=True, **kwargs)
      else:
        builtins.print(*objects, file=f, **kwargs)
        builtins.print(*objects, flush=True, **kwargs)
  except FileNotFoundError:
    builtins.print(*objects, **kwargs)
  except UnicodeEncodeError:
    pass

def InprocServer32FromCLSID(clsid):
  try:
    key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "CLSID" + "\\" + clsid + "\\" + "InprocServer32")
    module = winreg.QueryValueEx(key, '')[0]
    print("  |-- InprocServer32: %s" % module)
  except:
    key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "CLSID" + "\\" + clsid + "\\" + "LocalServer32")
    module = winreg.QueryValueEx(key, '')[0]
    print("  |-- LocalServer32: %s" % module)
  return module.split('\\')[-1]

def parseHKEY(path):
    hkey = path.split('\\')[0].lower()
    if hkey == "HKEY_CLASSES_ROOT".lower() or hkey == "HKCR".lower():
      hkey = winreg.HKEY_CLASSES_ROOT
    if hkey == "HKEY_CURRENT_USER".lower() or hkey == "HKCU".lower():
      hkey = winreg.HKEY_CURRENT_USER
    if hkey == "HKEY_LOCAL_MACHINE".lower() or hkey == "HKLM".lower():
      hkey = winreg.HKEY_LOCAL_MACHINE
    if hkey == "HKEY_USERS".lower() or hkey == "HKU".lower():
      hkey = winreg.HKEY_USERS
    return hkey

def search():
  for file in glob.glob('.\\' + config.WORK_DIR + '\\' + '*[degkl]_*.txt'):
    f = open(file, 'r', encoding='utf-8')
    text = f.read()

    ## Copied from Django's URLValidator class
    ul = "\u00a1-\uffff"

    # IP patterns
    ipv4_re = (
      r"(?:0|25[0-5]|2[0-4][0-9]|1[0-9]?[0-9]?|[1-9][0-9]?)"
      r"(?:\.(?:0|25[0-5]|2[0-4][0-9]|1[0-9]?[0-9]?|[1-9][0-9]?)){3}"
    )
    ipv6_re = r"\[[0-9a-f:.]+\]"

    # Host patterns
    hostname_re = (
      r"[a-z" + ul + r"0-9](?:[a-z" + ul + r"0-9-]{0,61}[a-z" + ul + r"0-9])?"
    )

    # Max length for domain name labels is 63 characters per RFC 1034 sec. 3.1
    domain_re = r"(?:\.(?!-)[a-z" + ul + r"0-9-]{1,63}(?<!-))*"
    tld_re = (
      r"\."
      r"(?!-)"
      r"(?:[a-z" + ul + "-]{2,63}"
      r"|xn--[a-z0-9]{1,59})"
      r"(?<!-)"
      r"\.?"
    )
    host_re = "(" + hostname_re + domain_re + tld_re + "|localhost)"

    url_re = re.compile(
      r"(?:['\"]?)"
      r"(?:https?|ftps?)://"
      r"(?:[^\s:@/]+(?::[^\s:@/]*)?@)?"
      r"(?:" + ipv4_re + "|" + ipv6_re + "|" + host_re + ")"
      r"(?::[0-9]{1,5})?"
      r"(?:[/?#][^,\s]*)?"
      r"(?:['\"]?)",
      re.IGNORECASE
    )

    domain_re = re.compile(
      r"(?:['\"]?)"
      r"(?:" + host_re + ")"
    )

    ip_re = re.compile(
      r"(?:" + ipv4_re + ")"
    )

    urls     = [x.group() for x in url_re.finditer(text)]
    keywords = [x.group() for x in domain_re.finditer(text)]
    ips      = [x.group() for x in ip_re.finditer(text)]

    if (len(keywords) > 0 or len(ips) > 0 or len(urls) > 0):
      print(" [*] Searching for IOCs in '%s'..." % file)
      for keyword in keywords:
        keyword = re.sub(r'[\'"();]', '', keyword).encode('ascii', errors='ignore').decode()
        print("  [+] Keyword: %s" % keyword)
      for ip in ips:
        print("  [+] IP: %s" % ip)
      for url in urls:
        url = re.sub(r'[\'"();]', '', url).encode('ascii', errors='ignore').decode()
        print("  [+] URL: %s" % url)

def clean_frida_helper():
  for helper in glob.glob(os.path.expandvars("%TEMP%\\frida-*")):
    try:
      shutil.rmtree(helper)
    except PermissionError:
      pass

def cleanup():
  search()
  print(" [*] Cleaning up...")
  if len(config.REG_KEYS) > 0:
    for key in config.REG_KEYS:
      deleteKey(key)
  if len(config.FILES) > 0:
    for file in config.FILES:
      deleteFile(file)
  if len(config.FOLDERS) > 0:
    for folder in config.FOLDERS:
      deleteFolder(folder)
  clean_frida_helper()

def deleteFile(path):
  if os.path.exists(path):
    try:
      if not os.path.exists(config.WORK_DIR + "\\dropped_files"):
        os.mkdir(config.WORK_DIR + "\\dropped_files")
      shutil.copy2(path, config.WORK_DIR + "\\dropped_files")
      os.remove(path)
      print("  [+] Deleted file: %s" % path)
    except FileExistsError:
      pass
    except FileNotFoundError:
      pass

def deleteFolder(path):
  if os.path.exists(path):
    try:
      os.rmdir(path)
      print("  [+] Deleted folder: %s" % path)
    except FileNotFoundError:
      pass

def deleteKey(key):
  hkey = parseHKEY(key)
  subkey = '\\'.join(key.split('\\')[1:])
  try:
    winreg.DeleteKey(hkey, subkey)
  except FileNotFoundError:
    return
  print("  [+] Deleted registry key: %s" % key)

def deleteValue(path):
  hkey   = parseHKEY(path)
  subkey = '\\'.join(path.split('\\')[1:-1])
  value  = path.split('\\')[-1]

  try:
    key = winreg.OpenKey(
      hkey,
      subkey,
      0,
      winreg.KEY_QUERY_VALUE|winreg.KEY_SET_VALUE
    )
  except PermissionError:
    print("  |-- (Access is denied!)")
    return

  # pause for value to be written
  time.sleep(0.1)

  data = winreg.QueryValueEx(key, value)[0]
  reg_count = config.REG_COUNT + 1
  filename = 'reg_' + ("%d" % reg_count) + '.txt'
  with open('.\\' + config.WORK_DIR + '\\' + filename, 'w') as fd:
    fd.write("Value: %s\nData : %s" % (path, data))
  fd.close()
  print("  |>> Data written to \".\\%s\\%s\"" % (config.WORK_DIR, filename))
  winreg.DeleteValue(key, value)
  key.Close()
  print("  |-- (Deleted!)")

def decodePowerShell(encoded):
  decode_count = config.DECODE_COUNT + 1
  filename = 'decoded_' + ("%d" % decode_count) + '.txt'
  decoded = base64.b64decode(encoded).decode('utf-16le')
  with open('.\\' + config.WORK_DIR + '\\' + filename, 'w') as fd:
    fd.write(decoded)
  fd.close()
  print("  |>> Data written to \".\\%s\\%s\"" % (config.WORK_DIR, filename))

def print_banner():
  builtins.print("%s%s%s" % 
  (
    random.choice(extras.colors), 
    random.choice(extras.banners),
    extras.DEFAULT
  ))