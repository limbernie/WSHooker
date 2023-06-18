import argparse
import builtins
import glob
import frida
import os
import re
import shutil
import time
import random
import winreg

from colors import *

# overload builtins.print with extras
def print(*objects, **kwargs):
    ts = "%012.6fs" % time.perf_counter()
    if args.file:
        with open('.\\' + WORK_DIR + '\\' + args.file, 'a') as f:
            if args.timestamp:
                builtins.print(' '.join([ts, *objects]), file=f, **kwargs)
            else:
                builtins.print(*objects, file=f, **kwargs)
    if args.timestamp:
        return builtins.print(' '.join([ts, *objects]), flush=True, **kwargs)
    else:
        return builtins.print(*objects, flush=True, **kwargs)

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
    print("   |>> Data written to '%s\\%s'" % (WORK_DIR, filename))
    winreg.DeleteValue(key, value)
    key.Close()
    print("   |-- (Deleted!)")

class Instrumenter:
    # path to wscript.exe
    _WSCRIPT_PATH_WOW64 = "C:\\Windows\SysWOW64\\"
    _WSCRIPT_PATH = "C:\\Windows\System32\\"
    _WSCRIPT_EXE = 'wscript.exe'

    def __init__(self, hook):
        self.hook = hook
        self._device = frida.get_local_device()
        self._device.on("child-added", self._on_child_added)
        self._device.on("child-removed", self._on_child_removed)
        self._device.on("output", self._on_output)
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

        session = frida.attach(pid)
        session.enable_child_gating()
        session.on('detached', self.on_detached)
        script = session.create_script(self.hook)
        script.on('message', self.on_message)
        script.on('destroyed', self.on_destroyed)
        script.load()

        # sending config to script
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
            "work_dir"      : WORK_DIR,
            "extension"     : EXTENSION
        })

        # keep the process suspended until resumed
        while True:
            try:
                time.sleep(0.5)
                if self._process_terminated:
                    break
            except KeyboardInterrupt:
                print(" [*] Warning: Instrumentation script is destroyed")
                cleanup()
                break

        if not self._process_terminated:
            print("   [+] Killed process: %s" % pid)
            print(" [*] Exiting...")
            frida.kill(pid)

    def on_detached(self, message, data):
        cleanup()
        print("   [+] Killed process: %s" % pid)
        print(" [*] Exiting...")
        self._process_terminated = True

    def on_destroyed(self):
        print(" [*] Warning: Instrumentation script is destroyed")

    def on_message(self, message, data):
        if message['type'] == 'send':
            msg_data = message['payload']

            if msg_data['target'] == 'registry':
                if msg_data['action'] == 'delete':
                    if msg_data['type'] == 'key':
                        regkeys.append(msg_data['path'])
                    elif msg_data['type'] == 'value':
                        deleteValue(msg_data['path'])
                elif msg_data['action'] == 'search':
                    if msg_data['type'] == 'value':
                        InprocServer32FromCLSID(msg_data['clsid'])
            elif msg_data['target'] == 'file':
                if msg_data['action'] == 'delete':
                    if msg_data['path'] not in files:
                        files.append(msg_data['path'])
            elif msg_data['target'] == 'frida':
                if msg_data['action'] == 'resume':
                    print(' [*] Hooking process: %s' % pid)
                    frida.resume(pid)
                    print(' [*] Press Ctrl-C to kill the process...')
                    print(" +---------+")
                    print(" |  Trace  |")
                    print(" +---------+")
            elif msg_data['target'] == 'system':
                if msg_data['action'] == 'print':
                    try:
                        print(msg_data['message'])
                    except UnicodeEncodeError:
                        pass

    def _on_child_added(self, child):
        print(" [*] %s spawned child process: %s" % (pid, child.pid))
        frida.kill(child.pid)

    def _on_child_removed(self, child):
        print("   [+] Killed child process: %s" % child.pid)
        print("   |")

    def _on_output(self, pid, fd, data):
        print(" [*] output: pid={}, fd={}, data={}".format(pid, fd, repr(data)))

if __name__ == '__main__':
    clean_frida_helper()
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
        dest='file',
        help="write output trace to file"
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
        help="(dangerous) allow shell commands"
    )
    parser.add_argument(
        '--allow-sleep',
        dest="allow_sleep",
        action="store_true",
        help="allow WScript.Sleep()"
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
            # create working directory from filename of script
            WORK_DIR  = os.path.basename(args.script).rsplit('.', 1)[0]
            try:
                os.mkdir(WORK_DIR)
                status = ' [*] Working directory: %s' % WORK_DIR
            except FileExistsError:
                status = ' [*] Working directory already exists: %s' % WORK_DIR
            valid_extensions = ['js', 'vbs', 'wsf']
            try:
                EXTENSION = os.path.basename(args.script).rsplit('.', 1)[1]
            except:
                pass
            if EXTENSION.lower() not in valid_extensions:
                print(" [!] Error: Invalid extension or no extension")
                exit(1)

            # truncate file if it exists
            if args.file:
                f = open('.\\' + WORK_DIR + '\\' + args.file, 'w')
                f.seek(0, 0)
                f.truncate()
                f.close()

            # START
            if not args.no_banner:
                builtins.print("%s%s%s" % (
                    random.choice(colors), 
                    random.choice(banners),
                    DEFAULT))
            print(status)

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

            instrumenter.instrument(pid,
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
            args.file = False
            print(" [!] Error: No such file")
            exit(1)
    else:
        parser.print_usage()
        exit(1)
