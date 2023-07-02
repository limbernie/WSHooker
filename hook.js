var DEBUG_FLAG   = false;
var ALLOW_BADCOM = false;
var ALLOW_FILE   = false;
var ALLOW_NET    = false;
var ALLOW_PROC   = false;
var ALLOW_REG    = false;
var ALLOW_SHELL  = false;
var ALLOW_SLEEP  = false;
var DYNAMIC      = false;
var EXTENSION    = null;
var WORK_DIR     = null;
var eval_count   = 0;
var shell_count  = 0;
var sock_count   = 0;
var text_count   = 0;

// filter these functions from dynamic tracing
var filtered = {
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

recv('config', function onMessage(setting) {
  DEBUG_FLAG  = setting['debug'];
  debug(" [*] DEBUG_FLAG: " + DEBUG_FLAG);
  ALLOW_BADCOM = setting['allow_badcom'];
  debug(" [*] ALLOW_BADCOM: " + ALLOW_BADCOM);
  ALLOW_FILE = setting['allow_file'];
  debug(" [*] ALLOW_FILE: " + ALLOW_FILE);
  ALLOW_NET = setting['allow_net'];
  debug(" [*] ALLOW_NET: " + ALLOW_NET);
  ALLOW_PROC = setting['allow_proc'];
  debug(" [*] ALLOW_PROC: " + ALLOW_PROC);
  ALLOW_REG = setting['allow_reg'];
  debug(" [*] ALLOW_REG: " + ALLOW_REG);
  ALLOW_SHELL = setting['allow_shell'];
  debug(" [*] ALLOW_SHELL: " + ALLOW_SHELL);
  ALLOW_SLEEP = setting['allow_sleep'];
  debug(" [*] ALLOW_SLEEP: " + ALLOW_SLEEP);
  DYNAMIC = setting['dynamic'];
  debug(" [*] DYNAMIC: " + DYNAMIC);

  WORK_DIR  = setting['work_dir'];
  EXTENSION = setting['extension'];

  if (EXTENSION === 'js') {
    debug(" [*] ENGINE: JScript");
  } else if (EXTENSION === 'vbs') {
    debug(" [*] ENGINE: VBScript");
  } else if (EXTENSION === 'wsf') {
    debug(" [*] ENGINE: Windows Script File");
  }

  // manually load symbols
  Module.load('jscript.dll');     // JScript Engine
  Module.load('vbscript.dll');    // VBScript Engine
  Module.load('scrrun.dll');      // Scripting Runtime
  Module.load('wshom.ocx');       // Windows Script Host Runtime
  Module.load('wbemdisp.dll');    // WMI Query Language
  Module.load('msxml3.dll');      // MSXML 3.0
  Module.load('winhttpcom.dll');  // WinHttpRequest

  // hook these
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

  // done configuring; tell frida to resume process
  resume();
});

function log(message) {
  send({
    target : "system",
    action : "print",
    message: message
  });
}

function debug(message) {
  if (DEBUG_FLAG)
    log(message);
}

function deleteFile(path) {
  send({
    target : "file",
    action : "delete",
    path   : path
  });
}

function deleteFolder(path) {
  send({
    target : "folder",
    action : "delete",
    path   : path
  });
}

function deleteKey(path) {
  send({
    target : "registry",
    action : "delete",
    type : "key",
    path : path
  });
}

function deleteValue(path) {
  send({
    target : "registry",
    action : "delete",
    type: "value",
    path : path
  });
}

function getInprocServer32(clsid) {
  send({
    target : "registry",
    action : "search",
    type   : "value",
    clsid  : clsid
  });
}

function resume() {
  send({
    target : "frida",
    action : "resume"
  });
}

function loadModuleForAddress(address) {
  var modules = Process.enumerateModules();
  var i;
  for (i = 0; i < modules.length; i++) {
    if (address >= modules[i].base && address <= modules[i].base.add(modules[i].size)) {
      var modName = modules[i].path
      try {
        DebugSymbol.load(modName)
      } catch (e) {
        return;
      }
    }
    break;
    }
}

function bytesToCLSID(address) {
  if (address.isNull())
    return;

  var data = new Uint8Array(ptr(address).readByteArray(0x10));
  var clsid = "";
  clsid += "{";
  clsid += ChrToHexStr(data[3]) + ChrToHexStr(data[2]);
  clsid += ChrToHexStr(data[1]) + ChrToHexStr(data[0]) + '-';
  clsid += ChrToHexStr(data[5]) + ChrToHexStr(data[4]) + '-';
  clsid += ChrToHexStr(data[7]) + ChrToHexStr(data[6]) + '-';
  clsid += ChrToHexStr(data[8]) + ChrToHexStr(data[9]) + '-';
  clsid += ChrToHexStr(data[10]) + ChrToHexStr(data[11]);
  clsid += ChrToHexStr(data[12]) + ChrToHexStr(data[13]);
  clsid += ChrToHexStr(data[14]) + ChrToHexStr(data[15]);
  clsid += '}';

  return clsid;
}

function ChrToHexStr(chr) {
  var hstr = chr.toString(16);
  return hstr.length < 2 ? "0" + hstr : hstr;
}

function resolveName(dllName, name) {
  var moduleName = dllName.split('.')[0];
  var functionName = dllName + "!" + name;

  debug(" [*] Finding " + functionName);
  debug(" [*] Module.findExportByName " + functionName);
  var addr = Module.findExportByName(dllName, name);

  if (!addr || addr.isNull()) {
    debug("  [+] DebugSymbol.load " + dllName);

    try {
      DebugSymbol.load(dllName);
    } catch (e) {
      debug("  [-] DebugSymbol.load: " + err);
      return;
    }

    debug("  [+] DebugSymbol.load finished");

    if (functionName.indexOf('*') === -1) {
      try {
        debug("  [+] DebugSymbol.getFunctionByName: " + functionName);
        addr = DebugSymbol.getFunctionByName(moduleName + '!' + name);
        debug("  [+] DebugSymbol.getFunctionByName: addr = " + addr);
      } catch (e) {
        debug("  [-] DebugSymbol.getFunctionByName: " + err);
      }
    } else {
      try {
        debug("  [+] DebugSymbol.findFunctionsMatching: " + functionName);
        var addresses = DebugSymbol.findFunctionsMatching(name);
        addr = addresses[addresses.length - 1];
        debug("  [+] DebugSymbol.findFunctionsMatching: addr " + addr);
      } catch (e) {
        debug("  [-] DebugSymbol.findFunctionsMatching: " + err);
      }
    }
  }
  return addr;
}

function hookFunction(dllName, funcName, callback) {
  var symbolName = dllName + "!" + funcName;

  var addr = resolveName(dllName, funcName);
  if (!addr || addr.isNull()) {
    return;
  }

  debug(' [*] Interceptor.attach: ' + symbolName + '@' + addr);
  Interceptor.attach(addr, callback);
}

function write(count, type, data) {
  var file_path = '.\\' + WORK_DIR + '\\';
  var file_name =  type + '_' + count + ".txt";
  var file = new File(file_path + file_name, 'w');
  file.write(data);

  log("  |>> Data written to " + '"' + WORK_DIR + '\\' + file_name + '"');
  file.close();
}

function hookCOleScriptCompile() {
  hookFunction("jscript.dll", "COleScript::Compile", {
    onEnter: function(args) {
      log(" Call: " + "jscript.dll" + "!COleScript::Compile()");
      log("  |");
      
      write(++eval_count, "code", ptr(args[1]).readUtf16String());

      log("  |");
      if (DYNAMIC) hookDispCallFunc();
      hookCLSIDFromProgID();
    }
  });
  hookFunction("vbscript.dll", "COleScript::Compile", {
    onEnter: function(args) {
      log(" Call: " + "vbscript.dll" + "!COleScript::Compile()");
      log("  |");
      
      write(++eval_count, "code", ptr(args[1]).readUtf16String());

      log("  |");
      if (DYNAMIC) hookDispCallFunc();
      hookCLSIDFromProgID();
    }
  });
}

var WSAHOST_NOT_FOUND = 11001;

function hookGetAddrInfoExW() {
  var host;
  hookFunction('ws2_32.dll', "GetAddrInfoExW", {
    onEnter: function(args) {
      host = args[0].readUtf16String();
      log(" Call: ws2_32.dll!GetAddrInfoExW()");
      log("  |");
      log("  |-- Query: " + host);
    },
    onLeave: function(retval) {
      if (!ALLOW_NET) {
        log("  |-- (Sinkholed!)");
        retval.replace(WSAHOST_NOT_FOUND);
      }
      log("  |");
    }
  });
}

function hookWSASend() {
  hookFunction('ws2_32.dll', 'WSASend', {
    onEnter: function(args) {
      var socket = args[0];
      var buffers = args[2].toInt32();
      var size = ptr(args[1]).readInt();
      log(" Call: ws2_32.dll!WSASend()");
      log("  |");
      log("  |-- Socket : " + socket);
      log("  |-- Buffers: " + buffers);
      log("  |-- Size   : " + size);

      var lpwbuf = args[1].toInt32() + 4;
      var dptr = Memory.readInt(ptr(lpwbuf));
      var data = hexdump(ptr(dptr), { length: size });
      
      write(++sock_count, "sock", data);

      if (!ALLOW_NET) {
        var ptr_closesocket = Module.findExportByName("ws2_32.dll", "closesocket");
        var closesocket = new NativeFunction(ptr_closesocket, 'int', ['pointer']);
        closesocket(args[0]);
        log("  |-- (Socket terminated!)");
      }
      log("  |");
    }
  });
}

var SHOW = {
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
}

function hookShellExecuteExW() {
  hookFunction('shell32.dll', "ShellExecuteExW", {
    onEnter: function(args) {
      var shellinfo_ptr = args[0];
      var ptr_verb = Memory.readPointer(shellinfo_ptr.add(12));
      var ptr_file = Memory.readPointer(shellinfo_ptr.add(16));
      var ptr_params = Memory.readPointer(shellinfo_ptr.add(20));
      var nshow = Memory.readInt(shellinfo_ptr.add(28));
      var lpfile = Memory.readUtf16String(ptr(ptr_file));
      var lpparams = Memory.readUtf16String(ptr(ptr_params));
      var lpverb = Memory.readUtf16String(ptr(ptr_verb));
      
      var data = "";
      data += "Command: " + lpfile;
      data += "\n";
      data += "Params : " + lpparams;
      data += "\n";
      data += "Verb   : " + lpverb;
      data += "\n";
      data += "nShow  : " + SHOW[nshow];
      
      log(" Call: shell32.dll!ShellExecuteExW()");
      log("  |");
      
      write(++shell_count, "shell", data);
      
      // "runas" doesn't spawn child process - dangerous!
      if (lpverb.match(/open/i)) {
        if (ALLOW_SHELL) {
          try {
            ptr_verb.writeUtf16String("runas");
          } catch (e) {
            log(e);
          }
          log("  |-- (" + '"' + lpverb + '"' + " > " + '"runas")');
        }
      } else if (lpverb.match(/runas/i)) {
        if (!ALLOW_SHELL) {
          try {
            ptr_verb.writeUtf16String("open");
          } catch (e) {
            log(e);
          }
          log("  |-- (" + '"' + lpverb + '"' + " > " + '"open")');
        }
      }
      log("  |");
    }
  });
}

function hookCWshShellRegWrite() {
  hookFunction('wshom.ocx', "CWshShell::RegWrite", {
    onEnter: function(args) {
      var path = args[1].readUtf16String();
      
      log(" Call: wshom.ocx!CWshShell::RegWrite()");
      log("  |");
      
      if (path.slice(-1) == '\\') {
        log("  |-- Key: " + path);
        if (!ALLOW_REG)
          deleteKey(path);
      }
      else {
        log("  |-- Value: " + path);
        if (!ALLOW_REG)
          deleteValue(path);
      }
      
      log("  |");
    }
  });
}

/*
DWORD GetFinalPathNameByHandleW(
  [in]  HANDLE hFile,
  [out] LPWSTR lpszFilePath,
  [in]  DWORD  cchFilePath,
  [in]  DWORD  dwFlags
);
*/

function hookWriteFile() {
  hookFunction('kernel32.dll', "WriteFile", {
    onEnter: function(args) {
      var handle = args[0];
      var size = args[2].toInt32();
      
      var ptrGetFinalPathNameByHandleW = Module.findExportByName('kernel32.dll', 'GetFinalPathNameByHandleW');
      var GetFinalPathNameByHandleW = new NativeFunction(ptrGetFinalPathNameByHandleW, 'int', ['pointer', 'pointer', 'int', 'int']);

      var lpszFilePath = Memory.alloc(256);
      GetFinalPathNameByHandleW(handle, ptr(lpszFilePath), 256, 0x8);
      var path = lpszFilePath.readUtf16String();
      
      log(" Call: kernel32.dll!WriteFile()");
      log("  |");
      log("  |-- Handle: " + handle);
      log("  |-- Size  : " + size);
      log("  |-- Path  : " + path);
      
      if (!ALLOW_FILE)
        deleteFile(path);
      
      log("  |");
    }
  });
}

function hookCopyFileA() {
  hookFunction('scrrun.dll', "CFileSystem::CopyFileA", {
    onEnter: function(args) {
      var src = args[1].readUtf16String();
      var dst = args[2].readUtf16String();
      
      log(" Call: scrrun.dll!CFileSystem::CopyFileA()");
      log("  |");
      log("  |-- Source: " + src);
      log("  |-- Destination: " + dst);
      
      if (!ALLOW_FILE)
        deleteFile(dst);
      
      log("  |");
    }
  });
}

function hookMoveFileA() {
  hookFunction('scrrun.dll', "CFileSystem::MoveFileA", {
    onEnter: function(args) {
      var src = args[1].readUtf16String();
      var dst = args[2].readUtf16String();
      
      log(" Call: scrrun.dll!CFileSystem::MoveFileA()");
      log("  |");
      log("  |-- Source: " + src);
      log("  |-- Destination: " + dst);
      
      if (!ALLOW_FILE)
        deleteFile(dst);
      
      log("  |");
    }
  });
}

function hookCreateFolder() {
  hookFunction('scrrun.dll', "CFileSystem::CreateFolder", {
    onEnter: function(args) {
      var path = ptr(args[1]).readUtf16String();
      
      log(" Call: scrrun.dll!CFileSystem::CreateFolder()");
      log("  |");
      log("  |-- Path: " + path);
      
      if (!ALLOW_FILE)
        deleteFolder(path);
      
      log("  |");
    }
  });
}

/*
HRESULT CLSIDFromProgID(
  [in]  LPCOLESTR lpszProgID,
  [out] LPCLSID   lpclsid
);
*/

var CO_E_CLASSSTRING   = 0x800401F3;
var REGDB_E_WRITEREGDB = 0x80040151;
var S_OK = 0;
var BadProgIDs = {
  "internetexplorer.application" : 1,
  "internetexplorer.application.1" : 1,
  "schedule.service" : 1,
  "schedule.service.1" : 1,
  "windowsinstaller.installer" : 1
};

function hookCLSIDFromProgID() {
  var ptrCLSIDFromProgID = Module.findExportByName('ole32.dll', "CLSIDFromProgID");
  var CLSIDFromProgID = new NativeFunction(ptrCLSIDFromProgID, 'uint', ['pointer', 'pointer']);
  Interceptor.replace(ptrCLSIDFromProgID, new NativeCallback(function (lpszProgID, lpclsid) {
    var retval = CLSIDFromProgID(lpszProgID, lpclsid);
    var progid = lpszProgID.readUtf16String();
    var clsid  = bytesToCLSID(ptr(lpclsid))
    log(" Call: ole32.dll!CLSIDFromProgID()");
    log("  |");
    log("  |-- ProgID: " + progid);
    log("  |-- CLSID : " + clsid);
    getInprocServer32(clsid);

    if (progid.toLowerCase() in BadProgIDs) {
      if (!ALLOW_BADCOM) {
        log("  |-- (Bad ProgID terminated!)");
        retval = CO_E_CLASSSTRING;
      }
    }
    log("  |");
    return retval;
  }, 'uint', ['pointer', 'pointer'], 'stdcall'));
}

function hookDispCallFunc() {
  if (!("DispCallFunc" in filtered)) {
    filtered["DispCallFunc"] = 1;
    var ptrDispCallFunc = Module.findExportByName('oleaut32.dll', "DispCallFunc");
    Interceptor.attach(ptrDispCallFunc, {
      onEnter: function(args) {
        var pvInstance = args[0];
        var oVft = args[1];
        var instance = ptr(ptr(pvInstance).readULong());
        var vftbPtr = instance.add(oVft);
        var functionAddress = ptr(ptr(vftbPtr).readULong());

        loadModuleForAddress(functionAddress)
        var functionName = DebugSymbol.fromAddress(functionAddress)
        
        log(" Call: oleaut32.dll!DispCallFunc()");
        log("  |");
        log("  |-- Function: " + functionName);
        log("  |");

        // hook new functions here if they aren't already hooked
        if (!(functionName.name in filtered)) {
          filtered[functionName.name] = 1;
          Interceptor.attach(functionAddress, {
            onEnter: function(args) {
              log(" Call: " + functionName.moduleName + '!' + functionName.name + '()');
              log("  |");
              var i;
              for (i = 1; i < 3; i++) {
                var out;
                try {
                  out = args[i].readUtf16String();
                  if (out === '')
                    out = "NULL";
                  else if (out.length === 1)
                    out = null;
                } catch(e) {
                  out = null;
                }
                if (out) log("  |-- Arg: " + out);
              }
              log("  |");
            }
          });
        }
      }
    });
  }
}

var HRESULT = {
  0x00000000 : "S_OK",
  0x80004001 : "E_NOTIMPL",
  0x80004002 : "E_NOINTERFACE",
  0x80004003 : "E_POINTER",
  0x80004004 : "E_ABORT",
  0x80004005 : "E_FAIL",
  0x8000FFFF : "E_UNEXPECTED",
  0x80070005 : "E_ACCESSDENIED",
  0x80070006 : "E_HANDLE",
  0x8007000E : "E_OUTOFMEMORY",
  0x80070057 : "E_INVALIDARG",
  0x800401E4 : "MK_E_SYNTAX",
  0x80040154 : "REGDB_E_CLASSNOTREG",
  0x80040150 : "REGDB_E_READREGDB"
};

function hookCHostObjSleep() {
  hookFunction('wscript.exe', "CHostObj::Sleep", {
    onEnter: function(args) {
      log(" Call: wscript.exe!CHostObj::Sleep()");
      log("  |");
      log("  |-- intTime: " + args[1].toInt32() + "ms" +
        (ALLOW_SLEEP ? "" : " (Skipping to 0ms)"));
      if (!ALLOW_SLEEP)
        args[1] = ptr(0x0);
    },
    onLeave(retval) {
      log("  |-- HRESULT: " + HRESULT[retval.toInt32()]);
      log("  |");

    }
  });
}

function hookCSWbemServicesExecQuery() {
  hookFunction('wbemdisp.dll', 'CSWbemServices::ExecQuery', {
    onEnter: function(args) {
      log(" Call: wbemdisp.dll!CSWbemServices::ExecQuery()");
      log("  |");
      log("  |-- Query: " + args[1].readUtf16String());
      log("  |");
    }
  });
}

function hookXMLHttpOpen() {
  hookFunction('msxml3.dll', 'XMLHttp::open', {
    onEnter: function(args) {
      var verb = args[1].readUtf16String();
      var url  = args[2].readUtf16String();
      log(" Call: msxml3.dll!XMLHttp::open()");
      log("  |");
      log("  |-- Verb: " + verb);
      log("  |-- URL : " + url);
      log("  |");
    }
  });
}

function hookXMLHttpsetRequestHeader() {
  hookFunction('msxml3.dll', 'XMLHttp::setRequestHeader', {
    onEnter: function(args) {
      var header = args[1].readUtf16String();
      var value  = args[2].readUtf16String();
      log(" Call: msxml3.dll!XMLHttp::setRequestHeader()");
      log("  |");
      log("  |-- Header: " + header);
      log("  |-- Value : " + value);
      log("  |");
    }
  });
}

function hookXMLHttpSend() {
  hookFunction('msxml3.dll', 'XMLHttp::send', {
    onEnter: function(args) {
      log(" Call: msxml3.dll!XMLHttp::send()");
      log("  |");
      try {
        var data = args[3].readUtf16String();
        if (data)
          log("  |-- Data: " + data);
        log("  |");
      } catch(e) {
      log("  |");
      }
    }
  });
}

var FOLDERSPEC = {
  0x0 : "WindowsFolder",
  0x1 : "SystemFolder",
  0x2 : "TemporaryFolder"
};

function hookCFileSystemGetSpecialFolder() {
  hookFunction("scrrun.dll", "CFileSystem::GetSpecialFolder", {
    onEnter: function(args) {
      var folder = FOLDERSPEC[args[1].toInt32()];
      log(" Call: scrrun.dll!CFileSystem::GetSpecialFolder()");
      log("  |");
      log("  |-- Folder: " + folder);
      log("  |");
    }
  });
}

function hookCHttpRequestOpen() {
  hookFunction('winhttpcom.dll', 'CHttpRequest::Open', {
    onEnter: function(args) {
      var verb = args[1].readUtf16String();
      var url  = args[2].readUtf16String();
      log(" Call: winhttpcom.dll!CHttpRequest::Open()");
      log("  |");
      log("  |-- Verb: " + verb);
      log("  |-- URL : " + url);
      log("  |");
    }
  });
}

function hookCHttpRequestSetRequestHeader() {
  hookFunction('winhttpcom.dll', 'CHttpRequest::SetRequestHeader', {
    onEnter: function(args) {
      var header = args[1].readUtf16String();
      var value  = args[2].readUtf16String();
      log(" Call: winhttpcom.dll!CHttpRequest::SetRequestHeader()");
      log("  |");
      log("  |-- Header: " + header);
      log("  |-- Value : " + value);
      log("  |");
    }
  });
}

function hookCHttpRequestSend() {
  hookFunction('winhttpcom.dll', 'CHttpRequest::Send', {
    onEnter: function(args) {
      log(" Call: winhttpcom.dll!CHttpRequest::Send()");
      log("  |");
      try {
        var data = args[3].readUtf16String();
        if (data)
          log("  |-- Data: " + data);
        log("  |");
      } catch(e) {
        log("  |");
      }
    }
  });
}

/*
HRESULT MkParseDisplayName(
  [in]  LPBC      pbc,
  [in]  LPCOLESTR szUserName,
  [out] ULONG     *pchEaten,
  [out] LPMONIKER *ppmk
);
*/

var MK_E_SYNTAX = 0x800401E4;

function hookMkParseDisplayName() {
  var ptrMkParseDisplayName = Module.findExportByName('ole32.dll', "MkParseDisplayName");
  var MkParseDisplayName = new NativeFunction(ptrMkParseDisplayName, 'uint', ['pointer', 'pointer', 'pointer', 'pointer']);
  Interceptor.replace(ptrMkParseDisplayName, new NativeCallback(function(pbc, szUserName, pchEaten, ppmk) {
    var retval = MkParseDisplayName(pbc, szUserName, pchEaten, ppmk);
    var moniker = ptr(szUserName).readUtf16String();
    
    log(" Call: ole32.dll!MkParseDisplayName");
    log("  |");
    log("  |-- Moniker: " + moniker);
    
    // ProgIDFromCLSID() to expose bad ProgIDs from CLSID
    var ptrCLSIDFromString = Module.findExportByName('ole32.dll', "CLSIDFromString");
    var CLSIDFromString = new NativeFunction(ptrCLSIDFromString, 'uint', ['pointer', 'pointer']);
    var ptrProgIDFromCLSID = Module.findExportByName('ole32.dll', "ProgIDFromCLSID");
    var ProgIDFromCLSID = new NativeFunction(ptrProgIDFromCLSID, 'uint', ['pointer', 'pointer']);
    
    var clsid_re = /(new:)(\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\})/;
    var clsid;
    
    if (moniker.match(clsid_re)) {
      clsid = moniker.replace(clsid_re, "$2");
      log("  |-- CLSID  : " + clsid);
      
      var lpsz = Memory.allocUtf16String(clsid);
      var pclsid = Memory.alloc(16);
      var lplpszProgID = Memory.alloc(256);
      var result, szProgID;
      
      result = CLSIDFromString(lpsz, ptr(pclsid));
      result = ProgIDFromCLSID(pclsid, lplpszProgID);
      szProgID = ptr(lplpszProgID).readPointer().readUtf16String();
      
      if (result === S_OK)
        log("  |-- ProgID : " + szProgID);
      else {
        log("  |");
      }
      
      if (szProgID.toLowerCase() in BadProgIDs) {
        if (!ALLOW_BADCOM) {
          log("  |-- (Bad ProgID terminated!)");
          log("  |");
          retval = MK_E_SYNTAX;
          return retval;
        }
      }
    } else if (moniker.match(/win32_process/i)) {
        if (!ALLOW_PROC) {
          log("  |-- (Win32_Process blocked!)");
          log("  |");
          retval = MK_E_SYNTAX;
          return retval;
        }
    }
    log("  |");
  }, 'uint', ['pointer', 'pointer', 'pointer', 'pointer']));
}

function hookWriteLine() {
  hookFunction('scrrun.dll', "CTextStream::WriteLine", {
    onEnter: function(args) {
        log(" Call: scrrun.dll!CTextStream::WriteLine()");
        log("  |");
        
        write(++text_count, "text", ptr(args[1]).readUtf16String());

        log("  |");
    }
  });
}