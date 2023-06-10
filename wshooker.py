import argparse
import builtins
import os
import time
import frida
import random

from utils import *

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
                   disable_com=False,
                   disable_dns=False,
                   disable_eval=False,
                   disable_file=False,
                   disable_net=False,
                   disable_proc=False,
                   disable_reg=False,
                   disable_shell=False,
                   disable_sleep=False,
                   enable_dyn=False
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
            "disable_com"   : disable_com,
            "disable_dns"   : disable_dns,
            "disable_eval"  : disable_eval,
            "disable_file"  : disable_file,
            "disable_net"   : disable_net,
            "disable_proc"  : disable_proc,
            "disable_reg"   : disable_reg,
            "disable_shell" : disable_shell,
            "disable_sleep" : disable_sleep,
            "enable_dyn"    : enable_dyn,
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
        '--debug',
        dest="debug",
        action="store_true",
        help="display debug message"
    )
    parser.add_argument(
        '--disable-com',
        dest="disable_com",
        action="store_true",
        help="disable COM object termination (dangerous!)"
    )
    parser.add_argument(
        '--disable-dns',
        dest="disable_dns",
        action="store_true",
        help="disable DNS sinkhole (dangerous!)"
    )
    parser.add_argument(
        '--disable-eval',
        dest="disable_eval",
        action="store_true",
        help="disable eval() output"
    )
    parser.add_argument(
        '--disable-file',
        dest="disable_file",
        action="store_true",
        help="disable file copy/write protect (dangerous!)"
    )
    parser.add_argument(
        '--disable-net',
        dest="disable_net",
        action="store_true",
        help="disable socket termination (dangerous!)"
    )
    parser.add_argument(
        '--disable-proc',
        dest="disable_proc",
        action="store_true",
        help="disable Win32_Process termination (dangerous!)"
    )
    parser.add_argument(
        '--disable-reg',
        dest="disable_reg",
        action="store_true",
        help="disable registry write protect (dangerous!)"
    )
    parser.add_argument(
        '--disable-shell',
        dest="disable_shell",
        action="store_true",
        help="disable shell output"
    )
    parser.add_argument(
        '--disable-sleep',
        dest="disable_sleep",
        action="store_true",
        help="disable sleep skipping"
    )
    parser.add_argument(
        '--enable-dyn',
        dest="enable_dyn",
        action="store_true",
        help="enable dynamic hooking (verbose)"
    )
    parser.add_argument(
        '--enable-timestamp',
        dest="timestamp",
        action="store_true",
        help="enable timestamp in output trace"
    )
    parser.add_argument(
        '--no-banner',
        dest="no_banner",
        action="store_true",
        help="remove banner in output trace"
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

            # for your protection!
            if args.disable_dns and args.disable_net:
                print(" [!] Error: You can't disable DNS sinkhole AND socket termination")
                exit(1)

            # start
            if not args.no_banner:
                builtins.print(random.choice(colors) + banner + DEFAULT)
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
                                    args.disable_com,
                                    args.disable_dns,
                                    args.disable_eval,
                                    args.disable_file,
                                    args.disable_net,
                                    args.disable_proc,
                                    args.disable_reg,
                                    args.disable_shell,
                                    args.disable_sleep,
                                    args.enable_dyn
                                   )
        else:
            args.file = False
            print(" [!] Error: No such file")
            exit(1)
    else:
        parser.print_usage()
        exit(1)
