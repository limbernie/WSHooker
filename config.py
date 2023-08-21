"""config.py

WSHooker Configuration
"""
# Windows Registry keys to be deleted
REG_KEYS_TO_DELETE = []

# Number of Windows Registry values deleted
REG_VALUE_DELETE_COUNT = 0

# Number of PowerShell's `-EncodedCommand` decoded
DECODED_COUNT = 0

# Files to be deleted
FILES_TO_DELETE = []

# Folders to be deleted
FOLDERS_TO_DELETE = []

# Working directory
WORK_DIR = ""

# Valid extensions
VALID_EXTENSIONS = [".js", ".jse", ".vbs", ".vbe", ".wsf"]

# Script extension
EXTENSION = ""

# Name of folder containing traces
TRACES = "traces"

# File name of trace log
TRACE = ""

# Timestamp
TIMESTAMP = False

# Fixed width for aesthetics
FIXED_WIDTH = 10

# Separator character
SPACE = " "

# Indent size
INDENT = SPACE * 2

# Bad ProgIDs that evade detection based on parent-child process relationship.
# Add new ProgIDs to this list.
BAD_PROGIDS_LIST = [
    "Internetexplorer.Application",
    "Internetexplorer.Application.1",
    "Schedule.Service",
    "Schedule.Service.1",
    "Windowsinstaller.Installer",
]

# Transform the ProgIDs to lower case.
BAD_PROGIDS = [progid.lower() for progid in BAD_PROGIDS_LIST]

# Unregistered class
UNREGISTERED_CLASS = "{00000000-0000-0000-0000-000000000000}"

# Filter these functions from dynamic tracing.
# Add new functions to filter to this list.
FILTER = [
    "CWshShell::RegWrite",
    "CHostObj::Sleep",
    "CSWbemServices::ExecQuery",
    "CHostObj::CreateObject",
    "CWshShell::Run",
    "CShellDispatch::ShellExecuteW",
    "XMLHttp::open",
    "XMLHttp::setRequestHeader",
    "XMLHttp::send",
    "CFileSystem::GetSpecialFolder",
    "CFileSystem::CopyFileA",
    "CFileSystem::MoveFileA",
    "CFileSystem::CreateFolder",
    "CHttpRequest::Open",
    "CHttpRequest::SetRequestHeader",
    "CHttpRequest::Send",
    "CTextStream::Close",
    "CTextStream::Write",
    "CTextStream::WriteLine",
]

# Windows Script Host
SYSWOW64 = "C:\\Windows\\SysWOW64"
SYSTEM32 = "C:\\Windows\\System32"
WSHOST = ""

# Add some fun to life.
FUN = False

# JSON output
JSON = False
JSON_OUTPUT = {
    "start": "",
    "trace": [],
    "ioc": [],
}
