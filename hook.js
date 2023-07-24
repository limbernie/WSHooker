var ALLOW_BADCOM = false;
var ALLOW_FILE   = false;
var ALLOW_NET    = false;
var ALLOW_PROC   = false;
var ALLOW_REG    = false;
var ALLOW_SHELL  = false;
var ALLOW_SLEEP  = false;
var DEBUG        = false;
var DYNAMIC      = false;
var EXTENSION    = null;
var WORK_DIR     = null;

var eval_count   = 0;
var shell_count  = 0;
var sock_count   = 0;
var text_count   = 0;

// Filter these functions from dynamic tracing
var FILTER = 
{
  "CWshShell::RegWrite" : 1,
  "CHostObj::Sleep" : 1,
  "CSWbemServices::ExecQuery" : 1,
  "CHostObj::CreateObject" : 1,
  "CWshShell::Run" : 1,
  "CShellDispatch::ShellExecuteW" : 1,
  "XMLHttp::open" : 1,
  "XMLHttp::setRequestHeader" : 1,
  "XMLHttp::send" : 1,
  "CFileSystem::GetSpecialFolder" : 1,
  "CFileSystem::CopyFileA" : 1,
  "CFileSystem::MoveFileA" : 1,
  "CFileSystem::CreateFolder" : 1,
  "CHttpRequest::Open" : 1,
  "CHttpRequest::SetRequestHeader" : 1,
  "CHttpRequest::Send" : 1,
  "CTextStream::Close" : 1,
  "CTextStream::Write" : 1,
  "CTextStream::WriteLine" : 1
};

recv('config', function onMessage(setting) 
{
  DEBUG = setting['debug'];
  status(["DEBUG", '=', DEBUG].join(''));
  ALLOW_BADCOM = setting['allow_badcom'];
  status(["ALLOW_BADCOM", '=', ALLOW_BADCOM].join(''));
  ALLOW_FILE = setting['allow_file'];
  status(["ALLOW_FILE", '=', ALLOW_FILE].join(''));
  ALLOW_NET = setting['allow_net'];
  status(["ALLOW_NET", '=', ALLOW_NET].join(''));
  ALLOW_PROC = setting['allow_proc'];
  status(["ALLOW_PROC", '=', ALLOW_PROC].join(''));
  ALLOW_REG = setting['allow_reg'];
  status(["ALLOW_REG", '=', ALLOW_REG].join(''));
  ALLOW_SHELL = setting['allow_shell'];
  status(["ALLOW_SHELL", '=', ALLOW_SHELL].join(''));
  ALLOW_SLEEP = setting['allow_sleep'];
  status(["ALLOW_SLEEP", '=', ALLOW_SLEEP].join(''));
  DYNAMIC = setting['dynamic'];
  status(["DYNAMIC", '=', DYNAMIC].join(''));

  WORK_DIR  = setting['work_dir'];
  EXTENSION = setting['extension'];

  if (EXTENSION === 'js') 
  {
    status(["ENGINE", '=', "JScript"].join(''));
  } 
  else if (EXTENSION === 'vbs') 
  {
    status(["ENGINE", '=', "VBScript"].join(''));
  } 
  else if (EXTENSION === 'wsf') 
  {
    status(["ENGINE", '=', "Windows Script File"].join(''));
  }

  // Load these modules
  Module.load('jscript.dll');     // JScript Engine
  Module.load('vbscript.dll');    // VBScript Engine
  Module.load('scrrun.dll');      // Scripting Runtime
  Module.load('wshom.ocx');       // Windows Script Host Runtime
  Module.load('wbemdisp.dll');    // WMI Query Language
  Module.load('msxml3.dll');      // MSXML 3.0
  Module.load('winhttpcom.dll');  // WinHttpRequest

  // Hook these functions
  hookCOleScriptCompile();
  hookCHostObjSleep();
  hookWriteFile();
  hookCopyFileA();
  hookMoveFileA();
  hookGetAddrInfoExW();
  hookWSASend();
  hookShellExecuteExW();
  hookCWshShellRegWrite();
  hookCSWbemServicesExecQuery();
  hookXMLHttpOpen();
  hookXMLHttpsetRequestHeader();
  hookXMLHttpSend();
  hookCFileSystemGetSpecialFolder();
  hookCHttpRequestOpen();
  hookCHttpRequestSetRequestHeader();
  hookCHttpRequestSend();
  hookMkParseDisplayName();
  hookWriteLine();
  hookCreateFolder();

  // Configuration done; tell frida to resume
  resume();
});

function log(message) 
{
  send
  ({
    target : "system",
    action : "log",
    message: message
  });
}

function debug(message) 
{
  if (DEBUG) 
  {
    log(message);
  }
}

function decodePowerShell(encoded) 
{
  send
  ({
    target : "system",
    action : "decode",
    value  : encoded
  });
}

function deleteFile(path) 
{
  send
  ({
    target : "file",
    action : "delete",
    path   : path
  });
}

function deleteFolder(path) 
{
  send
  ({
    target : "folder",
    action : "delete",
    path   : path
  });
}

function deleteRegKey(path) 
{
  send
  ({
    target : "registry",
    action : "delete",
    type : "key",
    path : path
  });
}

function deleteRegValue(path) 
{
  send
  ({
    target : "registry",
    action : "delete",
    type: "value",
    path : path
  });
}

function printInprocServer32(clsid) 
{
  send
  ({
    target : "registry",
    action : "search",
    type   : "value",
    clsid  : clsid
  });
}

function resume() 
{
  send
  ({
    target : "frida",
    action : "resume"
  });
}

function loadModuleForAddress(address) 
{
  var modules = Process.enumerateModules();
  var i;
  for (i = 0; i < modules.length; i++) 
  {
    if (address >= modules[i].base && address <= modules[i].base.add(modules[i].size)) 
    {
      var modName = modules[i].path
      try 
      {
        DebugSymbol.load(modName)
      }
      catch (e) 
      {
        return;
      }
    }
    break;
  }
}

function action(action) 
{
  param("Action", action);
}

function call(module, name) 
{
  log(["Call", ':', ' ', module, '!', name, "()"].join('')); 
}

function whereis(filepath) 
{
  param("Data", ['"', filepath, '"'].join(''));
}

function param(type, value) 
{
  log(["|--", ' ', type, " => ", value].join(''));
}

function separator() 
{
  log('|');
}

function status(message) 
{
  debug(["[*]", ' ', message].join(''));
}

function info(message) 
{
  debug(["[+]", ' ', message].join(''));
}

function error(message)
{
  debug(["[-]", ' ', message].join(''));
}

function bytesToCLSID(address) 
{
  if (address.isNull()) 
  {
    return;
  }

  var data = new Uint8Array(ptr(address).readByteArray(0x10));
  var clsid = 
  [
    '{',
    chrToHexStr(data[3]),
    chrToHexStr(data[2]),
    chrToHexStr(data[1]), 
    chrToHexStr(data[0]),
    '-',
    chrToHexStr(data[5]),
    chrToHexStr(data[4]),
    '-',
    chrToHexStr(data[7]),
    chrToHexStr(data[6]),
    '-',
    chrToHexStr(data[8]),
    chrToHexStr(data[9]),
    '-',
    chrToHexStr(data[10]),
    chrToHexStr(data[11]),
    chrToHexStr(data[12]),
    chrToHexStr(data[13]),
    chrToHexStr(data[14]),
    chrToHexStr(data[15]),
    '}'
  ];

  return clsid.join('');
}

function chrToHexStr(chr) 
{
  var hstr = chr.toString(16);
  return hstr.length < 2 ? "0" + hstr : hstr;
}

function resolveName(dllName, name) 
{
  var moduleName = dllName.split('.')[0];
  var functionName = [dllName, '!', name].join('');

  status(["Finding", ' ', functionName].join(''));
  status(["Module.findExportByName", ' ', functionName].join(''));
  var addr = Module.findExportByName(dllName, name);

  if (!addr || addr.isNull()) 
  {
    info(["DebugSymbol.load", ' ', dllName].join(''));

    try 
    {
      DebugSymbol.load(dllName);
    }
    catch (e) 
    {
      error(["DebugSymbol.load", ' ', e].join(''));
      return;
    }

    info("DebugSymbol.load finished");

    if (functionName.indexOf('*') === -1) 
    {
      try 
      {
        addr = DebugSymbol.getFunctionByName([moduleName, '!', name].join(''));
        info(["DebugSymbol.getFunctionByName", ' ', functionName].join(''));
        info(["DebugSymbol.getFunctionByName", ' ', addr].join(''));
      }
      catch (e) 
      {
        error(["DebugSymbol.getFunctionByName", ' ', e].join(''));
      }
    }
    else 
    {
      try 
      {
        var addresses = DebugSymbol.findFunctionsMatching(name);
        addr = addresses[addresses.length - 1];
        info(["DebugSymbol.findFunctionsMatching", ' ', functionName].join(''));
        info(["DebugSymbol.findFunctionsMatching", ' ', addr].join(''));
      }
      catch (e) 
      {
        error(["DebugSymbol.findFunctionsMatching", ' ', e].join(''));
      }
    }
  }
  return addr;
}

function hookFunction(dllName, funcName, callback) 
{
  var symbolName = [dllName, '!', funcName].join('');

  var addr = resolveName(dllName, funcName);
  if (!addr || addr.isNull()) 
  {
    return;
  }
  status(["Interceptor.attach", ' ', symbolName, '@', addr].join(''));
  Interceptor.attach(addr, callback);
}

function writeToFile(count, type, data) 
{
  var directory = ['.\\', WORK_DIR].join('');
  var filename  = [type, '_', count, '.', "txt"].join('');
  var filepath  = [directory, '\\', filename].join('');
  var file      = new File(filepath, 'w');

  file.write(data);
  file.close();

  whereis(filepath);
}

function hookCOleScriptCompile() 
{
  hookFunction("jscript.dll", "COleScript::Compile", 
  {
    onEnter: function(args) 
    {
      call("jscript.dll", "COleScript::Compile");
      separator();
      writeToFile(++eval_count, "code", ptr(args[1]).readUtf16String());
      separator();
    }
  });
  hookFunction("vbscript.dll", "COleScript::Compile", 
  {
    onEnter: function(args) 
    {
      call("vbscript.dll", "COleScript::Compile");
      separator();
      writeToFile(++eval_count, "code", ptr(args[1]).readUtf16String());
      separator();
    }
  });
  if (DYNAMIC) 
  {
    hookDispCallFunc();
  }
  hookCLSIDFromProgID();
}

var WSAHOST_NOT_FOUND = 11001;

function hookGetAddrInfoExW() 
{
  var host;
  hookFunction('ws2_32.dll', "GetAddrInfoExW", 
  {
    onEnter: function(args) 
    {
      host = args[0].readUtf16String();
      call("ws2_32.dll", "GetAddrInfoExW");
      separator();
      param("Query", host);
    },
    onLeave: function(retval) 
    {
      if (!ALLOW_NET) 
      {
        action("Block");
        retval.replace(WSAHOST_NOT_FOUND);
      } else 
      {
        if (retval.toInt32() === WSAHOST_NOT_FOUND) 
        {
          param("Result", "WSAHOST_NOT_FOUND");
        }
      }
      separator();
    }
  });
}

function hookWSASend() 
{
  hookFunction('ws2_32.dll', 'WSASend', 
  {
    onEnter: function(args) 
    {
      var socket = args[0];
      var buffers = args[2].toInt32();
      var size = ptr(args[1]).readInt();
      
      call("ws2_32.dll", "WSASend");
      separator();
      param("Socket", socket);
      param("Buffers", buffers);
      param("Size", size);

      var lpwbuf = args[1].toInt32() + 4;
      var dptr = Memory.readInt(ptr(lpwbuf));
      var data = hexdump(ptr(dptr), { length: size });
      
      writeToFile(++sock_count, "sock", data);

      if (!ALLOW_NET) 
      {
        var ptr_closesocket = Module.findExportByName("ws2_32.dll", "closesocket");
        var closesocket = new NativeFunction(ptr_closesocket, 'int', ['pointer']);
        closesocket(args[0]);
        action("Block)");
      }
      separator();
    }
  });
}

var SHOW = 
{
  0  : "SW_HIDE",
  1  : "SW_SHOWNORMAL",
  2  : "SW_SHOWMINIMIZED",
  3  : "SW_SHOWMAXIMIZED",
  4  : "SW_SHOWNOACTIVATE",
  5  : "SW_SHOW",
  6  : "SW_MINIMIZE",
  7  : "SW_SHOWMINNOACTIVE",
  8  : "SW_SHOWNA",
  9  : "SW_RESTORE",
  10 : "SW_SHOWDEFAULT"
};

function hookShellExecuteExW() 
{
  hookFunction('shell32.dll', "ShellExecuteExW", 
  {
    onEnter: function(args) 
    {
      var shellinfo_ptr = args[0];
      var ptr_verb = Memory.readPointer(shellinfo_ptr.add(12));
      var ptr_file = Memory.readPointer(shellinfo_ptr.add(16));
      var ptr_params = Memory.readPointer(shellinfo_ptr.add(20));
      var nshow = Memory.readInt(shellinfo_ptr.add(28));
      var lpfile = Memory.readUtf16String(ptr(ptr_file));
      var lpparams = Memory.readUtf16String(ptr(ptr_params));
      var lpverb = Memory.readUtf16String(ptr(ptr_verb));
      
      var data = 
      [
        "Command", '=', lpfile,   '\n',
        "Params" , '=', lpparams, '\n',
        "Verb"   , '=', lpverb,   '\n',
        "nShow"  , '=', SHOW[nshow]
      ];
      
      call("shell32.dll", "ShellExecuteExW");
      separator();
      
      writeToFile(++shell_count, "shell", data.join(''));
      
      var encodedCommand_re = /.*powershell.*-e[nc]*\s+(.*)/i;
      var encodedCommand;
      if (lpparams.match(encodedCommand_re)) 
      {
        encodedCommand = lpparams.replace(encodedCommand_re, "$1");
        decodePowerShell(encodedCommand);
      }
      
      // "runas" doesn't spawn child process - dangerous!
      if (lpverb.match(/open/i)) 
      {
        if (ALLOW_SHELL) 
        {
          try 
          {
            ptr_verb.writeUtf16String("runas");
          } 
          catch (e) 
          {
            error(e);
          }
          action("Allow (as Administrator)");
        }
        else 
        {
          action("Block");
        }
      } 
      else if (lpverb.match(/runas/i)) 
      {
        if (!ALLOW_SHELL) 
        {
          try 
          {
            ptr_verb.writeUtf16String("open");
          } 
          catch (e) 
          {
            error(e);
          }
          action("Block");
        }
        else {
          action("Allow (as Administrator)");
        }
      }
      separator();
    }
  });
}

function hookCWshShellRegWrite() 
{
  hookFunction('wshom.ocx', "CWshShell::RegWrite", 
  {
    onEnter: function(args) 
    {
      var path = args[1].readUtf16String();
      
      call("wshom.ocx", "CWshShell::RegWrite");
      separator();
      
      if (path.slice(-1) == '\\') 
      {
        param("Key", path);
        if (!ALLOW_REG) 
        {
          deleteRegKey(path);
        }
      }
      else 
      {
        param("Value", path);
        if (!ALLOW_REG) 
        {
          deleteRegValue(path);
        }
      }
      separator();
    }
  });
}

/*
DWORD GetFinalPathNameByHandleW
(
  [in]  HANDLE hFile,
  [out] LPWSTR lpszFilePath,
  [in]  DWORD  cchFilePath,
  [in]  DWORD  dwFlags
);
*/

function hookWriteFile() 
{
  hookFunction('kernel32.dll', "WriteFile", 
  {
    onEnter: function(args) 
    {
      var handle = args[0];
      var size = args[2].toInt32();
      
      var ptrGetFinalPathNameByHandleW = Module.findExportByName('kernel32.dll', 'GetFinalPathNameByHandleW');
      var GetFinalPathNameByHandleW = new NativeFunction(ptrGetFinalPathNameByHandleW, 'int', ['pointer', 'pointer', 'int', 'int']);

      var lpszFilePath = Memory.alloc(256);
      GetFinalPathNameByHandleW(handle, ptr(lpszFilePath), 256, 0x8);
      var path = lpszFilePath.readUtf16String();
      
      call("kernel32.dll", "WriteFile");
      separator();
      param("Handle", handle);
      param("Size", size);
      param("Path", path);
      separator();
      
      if (!ALLOW_FILE) 
      {
        deleteFile(path);
      }
    }
  });
}

function hookCopyFileA() 
{
  hookFunction('scrrun.dll', "CFileSystem::CopyFileA", 
  {
    onEnter: function(args) 
    {
      var src = args[1].readUtf16String();
      var dst = args[2].readUtf16String();
      
      call("scrrun.dll", "CFileSystem::CopyFileA");
      separator();
      param("From", src);
      param("To", dst);
      separator();
      
      if (!ALLOW_FILE) 
      {
        deleteFile(dst);
      }
    }
  });
}

function hookMoveFileA() 
{
  hookFunction('scrrun.dll', "CFileSystem::MoveFileA", 
  {
    onEnter: function(args) 
    {
      var src = args[1].readUtf16String();
      var dst = args[2].readUtf16String();
      
      call("scrrun.dll", "CFileSystem::MoveFileA");
      separator();
      param("From", src);
      param("To", dst);
      separator();
      
      if (!ALLOW_FILE) 
      {
        deleteFile(dst);
      }
    }
  });
}

function hookCreateFolder() 
{
  hookFunction('scrrun.dll', "CFileSystem::CreateFolder", 
  {
    onEnter: function(args) 
    {
      var path = ptr(args[1]).readUtf16String();
      
      call("scrrun.dll", "CFileSystem::CreateFolder");
      separator();
      param("Path", path);
      separator();
      
      if (!ALLOW_FILE) 
      {
        deleteFolder(path);
      }
    }
  });
}

/*
HRESULT CLSIDFromProgID
(
  [in]  LPCOLESTR lpszProgID,
  [out] LPCLSID   lpclsid
);
*/

var CO_E_CLASSSTRING   = 0x800401F3;
var S_OK = 0;
var BADPROGID = 
{
  "internetexplorer.application"   : 1,
  "internetexplorer.application.1" : 1,
  "schedule.service"               : 1,
  "schedule.service.1"             : 1,
  "windowsinstaller.installer"     : 1
};

function hookCLSIDFromProgID() 
{
  var ptrCLSIDFromProgID = Module.findExportByName('ole32.dll', "CLSIDFromProgID");
  var CLSIDFromProgID = new NativeFunction(ptrCLSIDFromProgID, 'uint', ['pointer', 'pointer']);
  Interceptor.replace(ptrCLSIDFromProgID, new NativeCallback(function (lpszProgID, lpclsid) 
  {
    var retval = CLSIDFromProgID(lpszProgID, lpclsid);
    var progid = lpszProgID.readUtf16String();
    var clsid  = bytesToCLSID(ptr(lpclsid))
    
    call("ole32.dll", "CLSIDFromProgID");
    separator();
    param("ProgID", progid);
    param("CLSID", clsid);
    
    printInprocServer32(clsid);

    if (progid.toLowerCase() in BADPROGID) 
    {
      if (!ALLOW_BADCOM) 
      {
        action("Block");
        retval = CO_E_CLASSSTRING;
      }
    }
    separator();
    return retval;
  }, 'uint', ['pointer', 'pointer'], 'stdcall'));
}

function hookDispCallFunc() 
{
  if (!("DispCallFunc" in FILTER)) 
  {
    FILTER["DispCallFunc"] = 1;
    hookFunction("oleaut32.dll", "DispCallFunc", 
    {
      onEnter: function(args) 
      {
        var pvInstance = args[0];
        var oVft = args[1];
        var instance = ptr(ptr(pvInstance).readULong());
        var vftbPtr = instance.add(oVft);
        var functionAddress = ptr(ptr(vftbPtr).readULong());

        loadModuleForAddress(functionAddress)
        var functionName = DebugSymbol.fromAddress(functionAddress)
        
        call("oleaut32.dll", "DispCallFunc");
        separator();
        param("Function", functionName);
        separator();

        // hook new functions here if they aren't already hooked
        if (!(functionName.name in FILTER)) 
        {
          FILTER[functionName.name] = 1;
          Interceptor.attach(functionAddress, 
          {
            onEnter: function(args) 
            {
              call(functionName.moduleName, functionName.name);
              separator();
              
              var i, arg;
              var MAX_ARGS = 5;
              for (i = 0; i < MAX_ARGS; i++)
              {
                if (args[i] === 0) 
                {
                  continue;
                }
                try {
                  arg = ptr(args[i]).readUtf16String();
                }
                catch (e) 
                {
                  continue;
                }
                if (arg && arg.length > 1) 
                {
                  param("Arg", arg);
                }
              }
              separator();
            }
          });
        }
      }
    });
  }
}

function hookCHostObjSleep() 
{
  hookFunction('wscript.exe', "CHostObj::Sleep", 
  {
    onEnter: function(args) 
    {
      call("wscript.exe", "CHostObj::Sleep");
      separator();
      param("Delay", args[1].toInt32() + "ms" + 
        ((!ALLOW_SLEEP) ? " (Skipping to 0ms)" : ""));
      if (!ALLOW_SLEEP) 
      {
        args[1] = ptr(0);
      }
      separator();
    }
  });
}

function hookCSWbemServicesExecQuery() 
{
  hookFunction('wbemdisp.dll', 'CSWbemServices::ExecQuery', 
  {
    onEnter: function(args) 
    {
      call("wbemdisp.dll", "CSWbemServices::ExecQuery");
      separator();
      param("Query", args[1].readUtf16String());
      separator();
    }
  });
}

function hookXMLHttpOpen() 
{
  hookFunction('msxml3.dll', 'XMLHttp::open', 
  {
    onEnter: function(args) 
    {
      var verb = args[1].readUtf16String();
      var url  = args[2].readUtf16String();
      
      call("msxml3.dll", "XMLHttp::open");
      separator();
      param("Verb", verb);
      param("URL", url);
      separator();
    }
  });
}

function hookXMLHttpsetRequestHeader() 
{
  hookFunction('msxml3.dll', 'XMLHttp::setRequestHeader', 
  {
    onEnter: function(args) 
    {
      var header = args[1].readUtf16String();
      var value  = args[2].readUtf16String();
      
      call("msxml3.dll", "XMLHttp::setRequestHeader");
      separator();
      param("Header", header);
      param("Value", value);
      separator();
    }
  });
}

function hookXMLHttpSend() 
{
  hookFunction('msxml3.dll', 'XMLHttp::send', 
  {
    onEnter: function(args) 
    {
      call("msxml3.dll", "XMLHttp::send");
      separator();
      try 
      {
        var data = args[3].readUtf16String();
        if (data) 
        {
          param("Data", data);
        }
        separator();
      } 
      catch (e) 
      {
        separator();
      }
    }
  });
}

var FOLDERSPEC = 
{
  0x0 : "WindowsFolder",
  0x1 : "SystemFolder",
  0x2 : "TemporaryFolder"
};

function hookCFileSystemGetSpecialFolder() 
{
  hookFunction("scrrun.dll", "CFileSystem::GetSpecialFolder", 
  {
    onEnter: function(args) 
    {
      var folder = FOLDERSPEC[args[1].toInt32()];
      
      call("scrrun.dll", "CFileSystem::GetSpecialFolder");
      separator();
      param("Folder", folder);
      separator();
    }
  });
}

function hookCHttpRequestOpen() 
{
  hookFunction('winhttpcom.dll', 'CHttpRequest::Open', 
  {
    onEnter: function(args) 
    {
      var verb = args[1].readUtf16String();
      var url  = args[2].readUtf16String();
      
      call("winhttpcom.dll", "CHttpRequest::Open");
      separator();
      param("Verb", verb);
      param("URL", url);
      separator();
    }
  });
}

function hookCHttpRequestSetRequestHeader() 
{
  hookFunction('winhttpcom.dll', 'CHttpRequest::SetRequestHeader', 
  {
    onEnter: function(args) 
    {
      var header = args[1].readUtf16String();
      var value  = args[2].readUtf16String();
      
      call("winhttpcom.dll", "CHttpRequest::SetRequestHeader");
      separator();
      param("Header", header);
      param("Value", value);
      separator();
    }
  });
}

function hookCHttpRequestSend() 
{
  hookFunction('winhttpcom.dll', 'CHttpRequest::Send', 
  {
    onEnter: function(args) 
    {
      call("winhttpcom.dll", "CHttpRequest::Send");
      separator();
      try 
      {
        var data = args[3].readUtf16String();
        if (data) 
        {
          param("Data", data);
        }
        separator();
      } 
      catch (e) 
      {
        separator();
      }
    }
  });
}

/*
HRESULT MkParseDisplayName
(
  [in]  LPBC      pbc,
  [in]  LPCOLESTR szUserName,
  [out] ULONG     *pchEaten,
  [out] LPMONIKER *ppmk
);
*/

var MK_E_SYNTAX = 0x800401E4;
var HRESULT = 
{
  0x00000000 : "S_OK",
  0x80040154 : "REGDB_E_CLASSNOTREG",
  0x80040150 : "REGDB_E_READREGDB"
};

function hookMkParseDisplayName() 
{
  var ptrMkParseDisplayName = Module.findExportByName('ole32.dll', "MkParseDisplayName");
  var MkParseDisplayName = new NativeFunction(ptrMkParseDisplayName, 'uint', ['pointer', 'pointer', 'pointer', 'pointer']);
  Interceptor.replace(ptrMkParseDisplayName, new NativeCallback(function(pbc, szUserName, pchEaten, ppmk) 
  {
    var retval = MkParseDisplayName(pbc, szUserName, pchEaten, ppmk);
    var moniker = ptr(szUserName).readUtf16String();
    
    call("ole32.dll", "MkParseDisplayName");
    separator();
    param("Moniker", moniker);
    
    // ProgIDFromCLSID() to expose bad ProgIDs from CLSID
    var ptrCLSIDFromString = Module.findExportByName('ole32.dll', "CLSIDFromString");
    var CLSIDFromString = new NativeFunction(ptrCLSIDFromString, 'uint', ['pointer', 'pointer']);
    var ptrProgIDFromCLSID = Module.findExportByName('ole32.dll', "ProgIDFromCLSID");
    var ProgIDFromCLSID = new NativeFunction(ptrProgIDFromCLSID, 'uint', ['pointer', 'pointer']);
    
    var clsid_re = /(new:)(\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\})/;
    var clsid;
    
    if (moniker.match(clsid_re)) 
    {
      clsid = moniker.replace(clsid_re, "$2");
      param("CLSID", clsid);
      
      var lpsz = Memory.allocUtf16String(clsid);
      var pclsid = Memory.alloc(16);
      var lplpszProgID = Memory.alloc(256);
      var result, szProgID;
      
      result = CLSIDFromString(lpsz, ptr(pclsid));
      result = ProgIDFromCLSID(pclsid, lplpszProgID);
      szProgID = ptr(lplpszProgID).readPointer().readUtf16String();
      
      if (HRESULT[result] === "S_OK") 
      {
        param("ProgID", szProgID);
      }
      else 
      {
        param("Result" + HRESULT[result]);
        separator();
      }
      
      if (szProgID.toLowerCase() in BADPROGID) 
      {
        if (!ALLOW_BADCOM) 
        {
          action("Block");
          separator();
          retval = MK_E_SYNTAX;
          return retval;
        }
      }
    } 
    else if (moniker.match(/win32_process/i)) 
    {
        if (!ALLOW_PROC) 
        {
          action("Block");
          separator();
          retval = MK_E_SYNTAX;
          return retval;
        }
    }
    separator();
  }, 'uint', ['pointer', 'pointer', 'pointer', 'pointer']));
}

function hookWriteLine() 
{
  hookFunction('scrrun.dll', "CTextStream::WriteLine", 
  {
    onEnter: function(args) 
    {
        call("scrrun.dll", "CTextStream::WriteLine");
        separator();
        writeToFile(++text_count, "text", ptr(args[1]).readUtf16String());
        separator();
    }
  });
}