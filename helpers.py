""" helpers.py

Helper Functions
"""
from argparse import ArgumentParser
from base64 import b64decode
from glob import glob
from os import makedirs, remove, rmdir
from os.path import basename, exists, expandvars
import re
from shutil import copy2, rmtree
from time import sleep
import winreg

import frida

import config
from patterns import DOMAIN_RE, IP_RE, URL_RE
from printer import info, param, status


def clean_up():
    """Clean up actions"""
    status("Cleaning up...")

    files_to_delete = list(set(config.FILES_TO_DELETE))
    folders_to_delete = list(set(config.FOLDERS_TO_DELETE))
    reg_keys_to_delete = list(set(config.REG_KEYS_TO_DELETE))

    for file in files_to_delete:
        delete_file(file)

    for folder in folders_to_delete:
        delete_folder(folder)

    for key in reg_keys_to_delete:
        delete_reg_key(key)


def delete_file(path):
    """Delete file."""
    if exists(path):
        dropped_files = f"{config.WORK_DIR}\\dropped_files"
        try:
            if not exists(dropped_files):
                makedirs(dropped_files)
            copy2(path, dropped_files)
            remove(path)
            info(f"Deleted file: {path}")
        except FileExistsError:
            pass
        except FileNotFoundError:
            pass


def delete_folder(path):
    """Delete folder."""
    if exists(path):
        try:
            rmdir(path)
            info(f"Deleted folder: {path}")
        except FileNotFoundError:
            pass


def delete_reg_key(key):
    """Delete registry key."""
    hkey = parse_hkey(key)
    subkey = "\\".join(key.split("\\")[1:])
    try:
        winreg.DeleteKey(hkey, subkey)
    except FileNotFoundError:
        return
    info(f"Deleted registry key: {key}")


def delete_reg_value(path):
    """Delete registry value."""
    if path is None:
        return
    hkey = parse_hkey(path)
    subkey = "\\".join(path.split("\\")[1:-1])
    value = path.split("\\")[-1]

    try:
        key = winreg.OpenKey(
            hkey, subkey, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE
        )
    except PermissionError:
        param("Access", "Denied")
        return

    # Pause for value to be written
    sleep(0.1)

    data = winreg.QueryValueEx(key, value)[0]
    config.REG_VALUE_DELETE_COUNT += 1
    reg_value_delete_count = config.REG_VALUE_DELETE_COUNT
    filename = f"reg_{reg_value_delete_count}.txt"
    with open(f"{config.WORK_DIR}\\{filename}", "w", encoding="utf-8") as file:
        file.write(f"Value: {path}\nData : {data}")
    param("WinReg", f"{filename}")
    winreg.DeleteValue(key, value)
    key.Close()
    param("Action", "Delete")


def decode_powershell(encoded):
    """Decode Base64-encoded PowerShell in -EncodedCommand."""
    if encoded is None:
        return
    config.DECODED_COUNT += 1
    decoded_count = config.DECODED_COUNT
    filename = f"ps_{decoded_count}.txt"
    decoded = b64decode(encoded).decode("utf-16le")
    with open(f"{config.WORK_DIR}\\{filename}", "w", encoding="utf-8") as file:
        file.write(decoded)
    param("PS", f"{filename}")


def find_ioc(wildcard="*[geckst]_*.txt"):
    """Search for IOC(s) in *.txt files."""
    _files = [
        _file
        for _file in glob(f"{config.WORK_DIR}\\{wildcard}")
        if "code_1.txt" not in _file
    ]
    for _file in _files:
        with open(_file, "r", encoding="utf-8") as file:
            content = file.read()

        urls = [x.group() for x in URL_RE.finditer(content)]
        keywords = [x.group() for x in DOMAIN_RE.finditer(content)]
        ipaddrs = [x.group() for x in IP_RE.finditer(content)]

        if len(keywords) > 0 or len(ipaddrs) > 0 or len(urls) > 0:
            status(f'Found IOC(s) in "{basename(_file)}"')
            for keyword in keywords:
                keyword = (
                    re.sub(r'[\'"();]', "", keyword).encode("utf-8", "ignore").decode()
                )
                info(f"Keyword: {keyword}")
            for ipaddr in ipaddrs:
                info(f"IP: {ipaddr}")
            for url in urls:
                url = re.sub(r'[\'"();]', "", url).encode("utf-8", "ignore").decode()
                info(f"URL: {url}")


def parse_arguments():
    """Parse WSHooker's arguments."""
    parser = ArgumentParser(description="WSHooker - Windows Script Hooking with Frida")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-p",
        "--pid",
        dest="pid",
        help="process id (reserved for future release)",
        type=int,
    )
    group.add_argument("-s", "--script", dest="script", help="path to malicious script")
    parser.add_argument(
        "-a",
        "--args",
        dest="args",
        help='arguments to malicious script, e.g., -a "arg1 arg2 arg3 ..."',
    )
    parser.add_argument(
        "-d", "--directory", dest="dir", help="directory or folder to hold output trace"
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="trace",
        default="trace.log",
        help="write output trace to file (default is trace.log)",
    )
    parser.add_argument(
        "--allow-bad-progid",
        dest="allow_bad_progid",
        action="store_true",
        help="(dangerous) allow known bad ProgID",
    )
    parser.add_argument(
        "--allow-file",
        dest="allow_file",
        action="store_true",
        help="(dangerous) allow file copy/move/write",
    )
    parser.add_argument(
        "--allow-net",
        dest="allow_net",
        action="store_true",
        help="(dangerous) allow network requests",
    )
    parser.add_argument(
        "--allow-proc",
        dest="allow_proc",
        action="store_true",
        help="(dangerous) allow Win32_Process",
    )
    parser.add_argument(
        "--allow-reg",
        dest="allow_reg",
        action="store_true",
        help="(dangerous) allow registry write",
    )
    parser.add_argument(
        "--allow-shell",
        dest="allow_shell",
        action="store_true",
        help="(dangerous) allow shell command to run as Administrator",
    )
    parser.add_argument(
        "--allow-sleep",
        dest="allow_sleep",
        action="store_true",
        help="(slow-down) allow WScript.Sleep()",
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        help="(verbose) display debug message",
    )
    parser.add_argument(
        "--dynamic",
        dest="dynamic",
        action="store_true",
        help="(verbose) enable dynamic tracing",
    )
    parser.add_argument(
        "--no-banner",
        dest="no_banner",
        action="store_true",
        help="remove banner in output trace",
    )
    parser.add_argument(
        "--timestamp",
        dest="timestamp",
        action="store_true",
        help="display timestamp in output trace",
    )
    parser.add_argument(
        "--wscript",
        dest="wscript",
        action="store_true",
        help="switch to wscript.exe (default is cscript.exe)",
    )
    args = parser.parse_args()
    return parser, args


def parse_hkey(path):
    """Parse HKEY from path."""
    hkey = path.split("\\")[0].lower()
    if hkey == "HKEY_CLASSES_ROOT".lower() or hkey == "HKCR".lower():
        hkey = winreg.HKEY_CLASSES_ROOT
    if hkey == "HKEY_CURRENT_USER".lower() or hkey == "HKCU".lower():
        hkey = winreg.HKEY_CURRENT_USER
    if hkey == "HKEY_LOCAL_MACHINE".lower() or hkey == "HKLM".lower():
        hkey = winreg.HKEY_LOCAL_MACHINE
    if hkey == "HKEY_USERS".lower() or hkey == "HKU".lower():
        hkey = winreg.HKEY_USERS
    return hkey


def post_actions(delay_in_sec=0):
    """Post-instrumentation actions to perform with a delay for Frida removal."""
    find_ioc()

    clean_up()

    sleep(delay_in_sec)

    remove_frida()

    status("Bye!")


def print_inprocserver32_from_clsid(clsid):
    """Get InprocServer32/LocalServer32 from CLSID and then print."""
    if clsid == config.UNREGISTERED_CLASS:
        return
    clsid_path = f"CLSID\\{clsid}\\"
    try:
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"{clsid_path}InprocServer32")
        module = winreg.QueryValueEx(key, "")[0]
        param("InprocServer32", module)
    except FileNotFoundError:
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"{clsid_path}LocalServer32")
        module = winreg.QueryValueEx(key, "")[0]
        param("LocalServer32", module)


def remove_frida():
    """Clean up Frida residuals."""
    remove_frida_injectors()
    remove_frida_temp_files()


def remove_frida_injectors():
    """Delete Frida's injectors."""
    device = frida.get_local_device()
    for process in device.enumerate_processes():
        if "frida-" in process.name:
            frida.kill(process.pid)


def remove_frida_temp_files():
    """Delete Frida's temporary files."""
    for helper in glob(expandvars("%TEMP%\\frida-*")):
        try:
            rmtree(helper)
        except PermissionError:
            pass
