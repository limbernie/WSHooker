"""config.py

WSHooker Configuration
"""
# Windows Registry keys to be deleted
reg_keys_to_delete = []

# Number of Windows Registry values deleted
reg_value_delete_count = 0

# Number of PowerShell's `-EncodedCommand` decoded
decoded_count = 0

# Files to be deleted
files_to_delete = []

# Folders to be deleted
folders_to_delete = []

# Working directory
work_dir = ''

# Valid extensions
valid_extensions = [ "js", "jse", "vbs", "vbe", "wsh" ]

# Script extension
extension = ''

# Name of folder containing traces
traces = "traces"

# File name of trace log
trace = ''

# Timestamp
timestamp = False

# Fixed width for aesthetics
fixed_width = 8

# Separator character
space = ' '

# Indent size
indent = space * 2

# Bad ProgIDs that evade detection based on parent-child process relationship.
# Add new ProgID in lower case.
bad_progids = {
  "internetexplorer.application"   : 1,
  "internetexplorer.application.1" : 1,
  "schedule.service"               : 1,
  "schedule.service.1"             : 1,
  "windowsinstaller.installer"     : 1
}

# Unregistered class
unregistered_class = "{00000000-0000-0000-0000-000000000000}"

# Filter these functions from dynamic tracing.
filter_from_tracing = {
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
wsh_path_wow64 = "C:\\Windows\\SysWOW64\\"
wsh_path = "C:\\Windows\\System32\\"
wsh_exe  = "cscript.exe"