import glob
import os
import re
import shutil
import winreg

# colors!
DEFAULT = '\033[0m'
BLACK = '\033[30m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
WHITE = '\033[97m'
DARK_RED = '\033[31m'
DARK_GREEN = '\033[32m'
DARK_YELLOW = '\033[33m'
DARK_BLUE = '\033[34m'
DARK_MAGENTA = '\033[35m'
DARK_CYAN = '\033[36m'
DARK_WHITE = '\033[37m'
BRIGHT_BLACK = '\033[90m'
BRIGHT_RED = '\033[91m'
BRIGHT_GREEN = '\033[92m'
BRIGHT_YELLOW = '\033[93m'
BRIGHT_BLUE = '\033[94m'
BRIGHT_MAGENTA = '\033[95m'
BRIGHT_CYAN = '\033[96m'

colors = [
DARK_RED,
DARK_GREEN, 
DARK_YELLOW,
DARK_BLUE,
DARK_MAGENTA, 
DARK_CYAN,
DARK_WHITE, 
BRIGHT_BLACK,
BRIGHT_RED,
BRIGHT_GREEN,
BRIGHT_YELLOW,
BRIGHT_BLUE,
BRIGHT_MAGENTA,
BRIGHT_CYAN
]

banner = '''

 __        ______  _   _             _             
 \ \      / / ___|| | | | ___   ___ | | _____ _ __ 
  \ \ /\ / /\___ \| |_| |/ _ \ / _ \| |/ / _ \ '__|
   \ V  V /  ___) |  _  | (_) | (_) |   <  __/ |   
    \_/\_/  |____/|_| |_|\___/ \___/|_|\_\___|_|   
                                                   

'''

# registry keys to be deleted
regkeys = []

# files to be deleted
files = []

# working directory
WORK_DIR = ''

# extension determines which engine to use
EXTENSION = ''

def InprocServer32FromCLSID(clsid):
    try:
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT,
            "CLSID" + "\\" + clsid + "\\" + "InprocServer32")
        module = winreg.QueryValueEx(key, '')[0]
        print("   |-- InprocServer32: %s" % module)
    except:
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT,
            "CLSID" + "\\" + clsid + "\\" + "LocalServer32")
        module = winreg.QueryValueEx(key, '')[0]
        print("   |-- LocalServer32: %s" % module)
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
    for file in glob.glob('.\\' + WORK_DIR + '\\' + '*[gkl]_*.txt'):
        f = open(file, 'r', encoding='utf-8')
        text = f.read()

        ''' from django's URLValidator class '''
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

        urls    = [x.group() for x in url_re.finditer(text)]
        domains = [x.group() for x in domain_re.finditer(text)]
        ips     = [x.group() for x in ip_re.finditer(text)]

        if (len(domains) > 0 or len(ips) > 0 or len(urls) > 0):
            print(" [*] Searching for IOCs in '%s'..." % file)
            for domain in domains:
                print("   [+] Keyword: %s" % domain.replace('"','').replace("'",''))
            for ip in ips:
                print("   [+] IP: %s" % ip)
            for url in urls:
                print("   [+] URL: %s" % url.replace('"','').replace("'",''))

def clean_frida_helper():
    # clean up frida-helper stuff as much as possible
    for helper in glob.glob(os.path.expandvars("%TEMP%\\frida-*")):
        try:
            shutil.rmtree(helper)
        except PermissionError:
            pass

def cleanup():
    search()
    print(" [*] Cleaning up...")
    if len(regkeys) > 0:
        for key in regkeys:
            deleteKey(key)
    if len(files) > 0:
        for file in files:
            deleteFile(file)
    clean_frida_helper()

def deleteFile(path):
    try:
        shutil.copy(path, WORK_DIR)
        os.remove(path)
        print("   [+] Deleted file: %s" % path)
    except FileNotFoundError:
        pass

def deleteKey(key):
    hkey = parseHKEY(key)
    subkey = '\\'.join(key.split('\\')[1:])
    try:
        winreg.DeleteKey(hkey, subkey)
    except FileNotFoundError:
        return
    print("   [+] Deleted registry key: %s" % key)

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
        print("   |-- (Access is denied!)")
        return

    # pause for value to be written
    time.sleep(0.1)

    data = winreg.QueryValueEx(key, value)[0]
    filename = 'reg_' + '_'.join(path.split('\\')[-2:]) + '.txt'
    with open('.\\' + WORK_DIR + '\\' + filename, 'w') as fd:
        fd.write(data)
    fd.close()
    print("   |-- Data : Data written to '%s\\%s'" % (WORK_DIR, filename))
    winreg.DeleteValue(key, value)
    key.Close()
    print("   |-- (Deleted!)")
