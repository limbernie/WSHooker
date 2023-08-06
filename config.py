# Registry keys to be deleted
REG_KEYS_TO_DELETE = []

# Number of Registry values deleted
REG_VALUE_COUNT = 0

# Number of -EncodedCommand decoded
DECODED_COUNT = 0

# Files to be deleted
FILES = []

# Folders to be deleted
FOLDERS = []

# Working directory
WORK_DIR = ''

# Script extension
EXTENSION = ''

# Name of folder containing traces
TRACES = "traces"

# Trace log
TRACE = ''

# Timestamp
TIMESTAMP = False

# Fixed width for aesthetics
FIXED_WIDTH = 8

# Space character
SPACE = ' '

# Indent size
INDENT = SPACE * 2

# Bad ProgIDs known to evade detection based on parent-child process relationship.
BAD_PROGID = \
{
  "InternetExplorer.Application".lower()   : 1,
  "InternetExplorer.Application.1".lower() : 1,
  "Schedule.Service".lower()               : 1,
  "Schedule.Service.1".lower()             : 1,
  "WindowsInstaller.Installer".lower()     : 1
}

# Filter these functions from dynamic tracing.
FILTER = \
{
  "CWshShell::RegWrite"            : 1,
  "CHostObj::Sleep"                : 1,
  "CSWbemServices::ExecQuery"      : 1,
  "CHostObj::CreateObject"         : 1,
  "CWshShell::Run"                 : 1,
  "CShellDispatch::ShellExecuteW"  : 1,
  "XMLHttp::open"                  : 1,
  "XMLHttp::setRequestHeader"      : 1,
  "XMLHttp::send"                  : 1,
  "CFileSystem::GetSpecialFolder"  : 1,
  "CFileSystem::CopyFileA"         : 1,
  "CFileSystem::MoveFileA"         : 1,
  "CFileSystem::CreateFolder"      : 1,
  "CHttpRequest::Open"             : 1,
  "CHttpRequest::SetRequestHeader" : 1,
  "CHttpRequest::Send"             : 1,
  "CTextStream::Close"             : 1,
  "CTextStream::Write"             : 1,
  "CTextStream::WriteLine"         : 1
}

# Windows Script Host (WSH)
WSH_PATH_WOW64 = "C:\\Windows\\SysWOW64\\"
WSH_PATH = "C:\\Windows\\System32\\"
WSH_EXE  = "cscript.exe"