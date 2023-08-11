""" helpers.py

Helper Functions
"""
from base64 import b64decode
from glob import glob
from os import makedirs, remove, rmdir
from os.path import basename, exists, expandvars
import re
from shutil import copy2, rmtree
from time import sleep
import winreg

import config
from patterns import DOMAIN_RE, IP_RE, URL_RE
from printer import info, param, status


def print_inprocserver32_from_clsid(clsid):
    """Get InprocServer32/LocalServer32 from CLSID and then print."""
    if clsid == config.UNREGISTERED_CLASS:
        return
    clsid_path = "".join(["CLSID", "\\", clsid, "\\"])
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CLASSES_ROOT, "".join([clsid_path, "InprocServer32"])
        )
        module = winreg.QueryValueEx(key, "")[0]
        param("InprocServer32", module)
    except FileNotFoundError:
        key = winreg.OpenKey(
            winreg.HKEY_CLASSES_ROOT, "".join([clsid_path, "LocalServer32"])
        )
        module = winreg.QueryValueEx(key, "")[0]
        param("LocalServer32", module)


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


def search_for_ioc():
    """Search for IOCs in .txt files."""
    _files = [
        _file
        for _file in glob("".join([config.WORK_DIR, "\\", "*[geckst]_*.txt"]))
        if "code_1.txt" not in _file
    ]
    for _file in _files:
        with open(_file, "r", encoding="utf-8") as file:
            content = file.read()

        urls = [x.group() for x in URL_RE.finditer(content)]
        keywords = [x.group() for x in DOMAIN_RE.finditer(content)]
        ipaddrs = [x.group() for x in IP_RE.finditer(content)]

        if len(keywords) > 0 or len(ipaddrs) > 0 or len(urls) > 0:
            status(f'Searching for IOCs in "{basename(_file)}"...')
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


def clean_frida_temp_files():
    """Clean Frida's temporary files."""
    for helper in glob(expandvars("%TEMP%\\frida-*")):
        try:
            rmtree(helper)
        except PermissionError:
            pass


def clean_up():
    """Clean up actions"""
    search_for_ioc()
    status("Cleaning up...")

    reg_keys_to_delete = list(set(config.REG_KEYS_TO_DELETE))
    if len(reg_keys_to_delete) > 0:
        for key in reg_keys_to_delete:
            delete_reg_key(key)

    files_to_delete = list(set(config.FILES_TO_DELETE))
    if len(files_to_delete) > 0:
        for file in files_to_delete:
            delete_file(file)

    folders_to_delete = list(set(config.FOLDERS_TO_DELETE))
    if len(folders_to_delete) > 0:
        for folder in folders_to_delete:
            delete_folder(folder)
    clean_frida_temp_files()


def delete_file(path):
    """Delete file."""
    if exists(path):
        dropped_files = "".join([config.WORK_DIR, "\\", "dropped_files"])
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
    filename = "".join(["reg", "_", f"{reg_value_delete_count}", ".", "txt"])
    with open(
        "".join([config.WORK_DIR, "\\", filename]), "w", encoding="utf-8"
    ) as file:
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
    filename = "".join(["ps", "_", (f"{decoded_count}"), ".", "txt"])
    decoded = b64decode(encoded).decode("utf-16le")
    with open(
        "".join([config.WORK_DIR, "\\", filename]), "w", encoding="utf-8"
    ) as file:
        file.write(decoded)
    param("PS", f"{filename}")
