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
# Add new ProgID in lower case.
BAD_PROGIDS = {
    "internetexplorer.application": 1,
    "internetexplorer.application.1": 1,
    "schedule.service": 1,
    "schedule.service.1": 1,
    "windowsinstaller.installer": 1,
}

# Unregistered class
UNREGISTERED_CLASS = "{00000000-0000-0000-0000-000000000000}"

# Add and/or filter these functions from dynamic tracing.
FILTER_FROM_TRACING = {
    "CWshShell::RegWrite": 1,
    "CHostObj::Sleep": 1,
    "CSWbemServices::ExecQuery": 1,
    "CHostObj::CreateObject": 1,
    "CWshShell::Run": 1,
    "CShellDispatch::ShellExecuteW": 1,
    "XMLHttp::open": 1,
    "XMLHttp::setRequestHeader": 1,
    "XMLHttp::send": 1,
    "CFileSystem::GetSpecialFolder": 1,
    "CFileSystem::CopyFileA": 1,
    "CFileSystem::MoveFileA": 1,
    "CFileSystem::CreateFolder": 1,
    "CHttpRequest::Open": 1,
    "CHttpRequest::SetRequestHeader": 1,
    "CHttpRequest::Send": 1,
    "CTextStream::Close": 1,
    "CTextStream::Write": 1,
    "CTextStream::WriteLine": 1,
}

# Windows Script Host (WSH)
WSH_PATH_WOW64 = "C:\\Windows\\SysWOW64\\"
WSH_PATH = "C:\\Windows\\System32\\"
WSH_EXE = "cscript.exe"
