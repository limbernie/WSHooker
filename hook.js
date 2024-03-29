/*
 * hook.js - Frida instrumentation script
 */

/*
 * Global variables
 */
let ALLOW_BAD_PROGID = false;
let ALLOW_FILE = false;
let ALLOW_NET = false;
let ALLOW_PROC = false;
let ALLOW_REG_WRITE = false;
let ALLOW_SHELL_EXEC = false;
let ALLOW_SLEEP = false;
let DEBUG = false;
let DYNAMIC = false;
let BAD_PROGIDS, EXTENSION, FILTER, FIXED_WIDTH, WORK_DIR, WSHOST;

/*
 * File write counters
 */
let CODE_COUNT = 0;
let EXEC_COUNT = 0;
let SOCK_COUNT = 0;
let TEXT_COUNT = 0;

/*
 * Configuration
 */
recv("config", function onMessage(setting) {
  DEBUG = setting["debug"];
  status("DEBUG" + "=" + DEBUG);
  DYNAMIC = setting["dynamic"];
  status("DYNAMIC" + "=" + DYNAMIC);
  ALLOW_BAD_PROGID = setting["allow_bad_progid"];
  status("ALLOW_BAD_PROGID" + "=" + ALLOW_BAD_PROGID);
  ALLOW_FILE = setting["allow_file"];
  status("ALLOW_FILE" + "=" + ALLOW_FILE);
  ALLOW_NET = setting["allow_net"];
  status("ALLOW_NET" + "=" + ALLOW_NET);
  ALLOW_PROC = setting["allow_proc"];
  status("ALLOW_PROC" + "=" + ALLOW_PROC);
  ALLOW_REG_WRITE = setting["allow_reg_write"];
  status("ALLOW_REG_WRITE" + "=" + ALLOW_REG_WRITE);
  ALLOW_SHELL_EXEC = setting["allow_shell_exec"];
  status("ALLOW_SHELL_EXEC" + "=" + ALLOW_SHELL_EXEC);
  ALLOW_SLEEP = setting["allow_sleep"];
  status("ALLOW_SLEEP" + "=" + ALLOW_SLEEP);

  BAD_PROGIDS = new Set(JSON.parse(setting["bad_progids"]));
  EXTENSION = setting["extension"];
  FILTER = new Set(JSON.parse(setting["filter"]));
  FIXED_WIDTH = setting["fixed_width"];
  WORK_DIR = setting["work_dir"];
  WSHOST = setting["wshost"];

  if (EXTENSION.match(/js/)) {
    status("ENGINE=JScript");
  }
  else if (EXTENSION.match(/vb/)) {
    status("ENGINE=VBScript");
  }
  else if (EXTENSION.match(/wsf/)) {
    status("ENGINE=Windows Script File");
  }

  /* Load these modules; debug symbols are needed. */
  Module.load("jscript.dll");     // JScript Engine
  Module.load("vbscript.dll");    // VBScript Engine
  Module.load("scrrun.dll");      // Scripting Runtime
  Module.load("wshom.ocx");       // Windows Script Host Runtime
  Module.load("wbemdisp.dll");    // WMI Query Language
  Module.load("msxml3.dll");      // MSXML 3.0
  Module.load("winhttpcom.dll");  // WinHttpRequest

  /* Hook these essential functions. */
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
  hookCShellDispatchNameSpace();

  /* We're done here; tell frida to resume. */
  resume();
});

function resume() {
  send
    ({
      action: "resume"
    });
}

/* 
 * Print functions for output trace.
 */
function log(message) {
  send
    ({
      action: "log",
      parameter: message
    });
}

function action(action) {
  param("Action", action);
}

function call(module, functionName) {
  log("Call: " + module + "!" + functionName + "()");
}

/* 
 * String manipulation methods.
*/
String.prototype.center = function (width, c = ' ') {
  let pad = width - Math.ceil((width - this.length) / 2);
  return this.padStart(pad, c).padEnd(width, c);
};

String.prototype.capitalize = function () {
  return this.charAt(0).toUpperCase() + this.toLowerCase().slice(1);
};

String.prototype.removeprefix = function (prefix) {
  if (this.startsWith(prefix)) {
    return this.slice(prefix.length);
  } else {
    return this;
  }
};

function param(name, value) {
  log("|-- (" + name.center(FIXED_WIDTH) + ") => " + value);
}

function separator() {
  log('|');
}

/*
 * Print functions for debug message.
 * (**) => status
 * (II) => info
 * (EE) => error
 */
function debug(message) {
  if (DEBUG) {
    log(message);
  }
}

function status(message) {
  debug("(**) " + message);
}

function info(message) {
  debug("(II) " + message);
}

function error(message) {
  debug("(EE) " + message);
}

/*
 * Helper functions implemented in Python.
 */
function decodePowerShell(encoded) {
  send
    ({
      action: "decode_powershell",
      parameter: encoded
    });
}

function deleteFile(file) {
  send
    ({
      action: "delete_file",
      parameter: file
    });
}

function deleteFolder(folder) {
  send
    ({
      action: "delete_folder",
      parameter: folder
    });
}

function deleteRegKey(key) {
  send
    ({
      action: "delete_reg_key",
      parameter: key
    });
}

function deleteRegValue(value) {
  send
    ({
      action: "delete_reg_value",
      parameter: value
    });
}

function printInprocServer32FromCLSID(clsid) {
  send
    ({
      action: "print_inprocserver32_from_clsid",
      parameter: clsid
    });
}

/*
 * Helper functions implemented in JavaScript
 */
function checkCopyHereOptions(options) {
  const flags = {
    4: "Do not display a progress dialog box.",
    8: "Give the file being operated on a new name in a move, copy, or rename operation if a file with the target name already exists.",
    16: 'Respond with "Yes to All" for any dialog box that is displayed.',
    64: "Preserve undo information, if possible.",
    128: "Perform the operation on files only if a wildcard file name (*.*) is specified.",
    256: "Display a progress dialog box but do not show the file names.",
    512: "Do not confirm the creation of a new directory if the operation requires one to be created.",
    1024: "Do not display a user interface if an error occurs.",
    2048: "Do not copy the security attributes of the file.",
    4096: "Only operate in the local directory. Do not operate recursively into subdirectories.",
    8192: "Do not copy connected files as a group. Only copy the specified files.",
  };

  for (const [key, value] of Object.entries(flags)) {
    if ((options & parseInt(key)) == parseInt(key)) {
      param(key, value);
    }

  }
}

function loadModuleForAddress(address) {
  let modules = Process.enumerateModules();

  for (let i = 0; i < modules.length; i++) {
    if (address >= modules[i].base && address <= modules[i].base.add(modules[i].size)) {
      let modName = modules[i].path
      try {
        DebugSymbol.load(modName)
      }
      catch (e) {
        error(e);
      }
    }
    break;
  }
}

function bytesToCLSID(address) {
  if (address.isNull()) {
    return;
  }

  let data = new Uint8Array(ptr(address).readByteArray(0x10));
  let clsid =
    [
      "{",
      chrToHexStr(data[3]),
      chrToHexStr(data[2]),
      chrToHexStr(data[1]),
      chrToHexStr(data[0]),
      "-",
      chrToHexStr(data[5]),
      chrToHexStr(data[4]),
      "-",
      chrToHexStr(data[7]),
      chrToHexStr(data[6]),
      "-",
      chrToHexStr(data[8]),
      chrToHexStr(data[9]),
      "-",
      chrToHexStr(data[10]),
      chrToHexStr(data[11]),
      chrToHexStr(data[12]),
      chrToHexStr(data[13]),
      chrToHexStr(data[14]),
      chrToHexStr(data[15]),
      "}"
    ];

  return clsid.join("");
}

function chrToHexStr(chr) {
  let hstr = chr.toString(16);
  return hstr.length < 2 ? "0" + hstr : hstr;
}

function resolveName(image, symbol) {
  let moduleName = image.split('.')[0];
  let functionName = image + "!" + symbol;

  status("Finding " + functionName);
  status("Module.findExportByName " + functionName);

  let addr = Module.findExportByName(image, symbol);

  if (!addr || addr.isNull()) {
    info("DebugSymbol.load " + image);

    try {
      DebugSymbol.load(image);
    }
    catch (e) {
      error("DebugSymbol.load " + e);
    }

    info("DebugSymbol.load finished");

    if (functionName.indexOf('*') === -1) {
      try {
        addr = DebugSymbol.getFunctionByName(moduleName + "!" + symbol);
        info("DebugSymbol.getFunctionByName " + functionName);
        info("DebugSymbol.getFunctionByName " + addr);
      }
      catch (e) {
        error("DebugSymbol.getFunctionByName " + e);
      }
    }
    else {
      try {
        let addresses = DebugSymbol.findFunctionsMatching(symbol);
        addr = addresses[addresses.length - 1];
        info("DebugSymbol.findFunctionsMatching " + functionName);
        info("DebugSymbol.findFunctionsMatching " + addr);
      }
      catch (e) {
        error("DebugSymbol.findFunctionsMatching " + e);
      }
    }
  }
  return addr;
}

function hookFunction(image, symbol, callback) {
  let symbolName = image + "!" + symbol;
  let addr = resolveName(image, symbol);

  if (!addr || addr.isNull()) {
    return;
  }

  status("Interceptor.attach " + symbolName + "@" + addr);
  Interceptor.attach(addr, callback);
}

function writeToFile(type, count, data) {
  let filename = type + "_" + count + ".txt";
  let filepath = WORK_DIR + "\\" + filename;
  let file = new File(filepath, 'w');

  file.write(data);
  file.close();

  param(type.capitalize(), filename);
}

/*
 * Hooks
 */
function hookCOleScriptCompile() {
  let jsmodule = "jscript.dll";
  const fnName = "COleScript::Compile";

  hookFunction(jsmodule, fnName,
    {
      onEnter: function (args) {
        call(jsmodule, fnName);
        separator();
        writeToFile("code", ++CODE_COUNT, ptr(args[1]).readUtf16String());
        separator();
      }
    });

  let vbmodule = "vbscript.dll";

  hookFunction(vbmodule, fnName,
    {
      onEnter: function (args) {
        call(vbmodule, fnName);
        separator();
        writeToFile("code", ++CODE_COUNT, ptr(args[1]).readUtf16String());
        separator();
      }
    });
  if (DYNAMIC) {
    hookDispCallFunc();
  }
  hookCLSIDFromProgID();
}

function hookGetAddrInfoExW() {
  const WSAHOST_NOT_FOUND = 11001;

  let module = "ws2_32.dll";
  let fnName = "GetAddrInfoExW";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let host = args[0].readUtf16String();
        call(module, fnName);
        separator();
        param("Query", host);
      },
      onLeave: function (retval) {
        if (!ALLOW_NET) {
          action("Block");
          retval.replace(WSAHOST_NOT_FOUND);
        } else {
          if (retval.toInt32() === WSAHOST_NOT_FOUND) {
            param("Result", "WSAHOST_NOT_FOUND");
          }
        }
        separator();
      }
    });
}

function hookWSASend() {
  let module = "ws2_32.dll";
  let fnName = "WSASend";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let socket = args[0];
        let buffers = args[2].toInt32();
        let size = ptr(args[1]).readInt();

        call(module, fnName);
        separator();
        param("Socket", socket);
        param("Buffer", buffers);
        param("Size", size);

        let lpwbuf = args[1].add(4);
        let dptr = Memory.readInt(ptr(lpwbuf));
        let data = hexdump(ptr(dptr), { length: size });

        writeToFile("sock", ++SOCK_COUNT, data);

        if (!ALLOW_NET) {
          let ptr_closesocket = Module.findExportByName("ws2_32.dll", "closesocket");
          let closesocket = new NativeFunction(ptr_closesocket, "int", ["pointer"]);
          closesocket(args[0]);
          action("Block)");
        }
        separator();
      }
    });
}

function hookShellExecuteExW() {
  const SHOW =
  {
    0: "SW_HIDE",
    1: "SW_SHOWNORMAL",
    2: "SW_SHOWMINIMIZED",
    3: "SW_SHOWMAXIMIZED",
    4: "SW_SHOWNOACTIVATE",
    5: "SW_SHOW",
    6: "SW_MINIMIZE",
    7: "SW_SHOWMINNOACTIVE",
    8: "SW_SHOWNA",
    9: "SW_RESTORE",
    10: "SW_SHOWDEFAULT"
  };

  let module = "shell32.dll";
  let fnName = "ShellExecuteExW";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let shellinfo_ptr = args[0];
        let ptr_verb = Memory.readPointer(shellinfo_ptr.add(12));
        let ptr_file = Memory.readPointer(shellinfo_ptr.add(16));
        let ptr_params = Memory.readPointer(shellinfo_ptr.add(20));
        let nshow = Memory.readInt(shellinfo_ptr.add(28));
        let lpfile = Memory.readUtf16String(ptr(ptr_file));
        let lpparams = Memory.readUtf16String(ptr(ptr_params));
        let lpverb = Memory.readUtf16String(ptr(ptr_verb));

        const data =
          [
            "Command", ': ', lpfile, '\n',
            "Params ", ': ', lpparams, '\n',
            "Verb   ", ': ', lpverb, '\n',
            "Style  ", ': ', SHOW[nshow]
          ];

        call(module, fnName);
        separator();

        writeToFile("exec", ++EXEC_COUNT, data.join(""));

        const encodedCommand_re = /.*powershell.*-e[nc]*\s+(.*)/i;
        let encodedCommand;
        if (lpparams.match(encodedCommand_re)) {
          encodedCommand = lpparams.replace(encodedCommand_re, "$1");
          decodePowerShell(encodedCommand);
        }

        /* (dangerous) enable_child_gating has no effect on "runas" */
        if (lpverb.match(/runas/i)) {
          try {
            ptr_verb.writeUtf16String("open");
          }
          catch (e) {
            error(e);
          }
        }
        separator();
      }
    });
}

function hookCWshShellRegWrite() {
  let module = "wshom.ocx";
  let fnName = "CWshShell::RegWrite";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let path = args[1].readUtf16String();

        call(module, fnName);
        separator();

        if (path.slice(-1) == '\\') {
          param("Key", path);
          if (!ALLOW_REG_WRITE) {
            deleteRegKey(path);
          }
        }
        else {
          param("Value", path);
          if (!ALLOW_REG_WRITE) {
            deleteRegValue(path);
          }
        }
        separator();
      }
    });
}

function hookWriteFile() {
  let module = "kernel32.dll";
  let fnName = "WriteFile";
  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let handle = args[0];
        let size = args[2].toInt32();

        let ptrGetFinalPathNameByHandleW = Module.findExportByName("kernel32.dll", "GetFinalPathNameByHandleW");
        let GetFinalPathNameByHandleW = new NativeFunction(ptrGetFinalPathNameByHandleW, "int", ["pointer", "pointer", "int", "int"]);

        let lpszFilePath = Memory.alloc(256);
        GetFinalPathNameByHandleW(handle, ptr(lpszFilePath), 256, 0x8);

        const prefix = "\\\\?\\";
        let path = lpszFilePath.readUtf16String().removeprefix(prefix);

        call(module, fnName);
        separator();
        param("Handle", handle);
        param("Size", size);
        param("Path", path);
        separator();

        if (!ALLOW_FILE) {
          deleteFile(path);
        }
      }
    });
}

function hookCopyFileA() {
  let module = "scrrun.dll";
  let fnName = "CFileSystem::CopyFileA";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let src = args[1].readUtf16String();
        let dst = args[2].readUtf16String();

        call(module, fnName);
        separator();
        param("From", src);
        param("To", dst);
        separator();

        if (!ALLOW_FILE) {
          deleteFile(dst);
        }
      }
    });
}

function hookMoveFileA() {
  let module = "scrrun.dll";
  let fnName = "CFileSystem::MoveFileA";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let src = args[1].readUtf16String();
        let dst = args[2].readUtf16String();

        call(module, fnName);
        separator();
        param("From", src);
        param("To", dst);
        separator();

        if (!ALLOW_FILE) {
          deleteFile(dst);
        }
      }
    });
}

function hookCreateFolder() {
  let module = "scrrun.dll";
  let fnName = "CFileSystem::CreateFolder";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let path = ptr(args[1]).readUtf16String();

        call(module, fnName);
        separator();
        param("Path", path);
        separator();

        if (!ALLOW_FILE) {
          deleteFolder(path);
        }
      }
    });
}

function hookCLSIDFromProgID() {
  const CO_E_CLASSSTRING = 0x800401F3;

  let module = "ole32.dll";
  let fnName = "CLSIDFromProgID";

  let ptrCLSIDFromProgID = Module.findExportByName(module, fnName);
  let CLSIDFromProgID = new NativeFunction(ptrCLSIDFromProgID, "uint", ["pointer", "pointer"]);

  Interceptor.replace(ptrCLSIDFromProgID, new NativeCallback(function (lpszProgID, lpclsid) {
    let retval = CLSIDFromProgID(lpszProgID, lpclsid);
    let progid = lpszProgID.readUtf16String();
    let clsid = bytesToCLSID(ptr(lpclsid))

    call(module, fnName);
    separator();
    param("ProgID", progid);
    param("CLSID", clsid);

    printInprocServer32FromCLSID(clsid);

    if (BAD_PROGIDS.has(progid.toLowerCase())) {
      if (!ALLOW_BAD_PROGID) {
        action("Block");
        retval = CO_E_CLASSSTRING;
      }
    }
    separator();
    return retval;
  }, "uint", ["pointer", "pointer"], "stdcall"));
}

function hookDispCallFunc() {
  if (!(FILTER.has("DispCallFunc"))) {
    FILTER.add("DispCallFunc");

    let module = "oleaut32.dll";
    let fnName = "DispCallFunc";

    hookFunction(module, fnName,
      {
        onEnter: function (args) {
          let pvInstance = args[0];
          let oVft = args[1];
          let instance = ptr(ptr(pvInstance).readULong());
          let vftbPtr = instance.add(oVft);
          let functionAddress = ptr(ptr(vftbPtr).readULong());

          loadModuleForAddress(functionAddress)
          let functionName = DebugSymbol.fromAddress(functionAddress)

          call(module, fnName);
          separator();
          param("Function", functionName);
          separator();

          /* Hook new functions here if they aren't already hooked. */
          if (!(FILTER.has(functionName.name))) {
            FILTER.add(functionName.name);
            Interceptor.attach(functionAddress,
              {
                onEnter: function (args) {
                  call(functionName.moduleName, functionName.name);
                  separator();

                  let i, arg;
                  let MAX_ARGS = 5;
                  for (i = 0; i < MAX_ARGS; i++) {
                    if (args[i].isNull()) {
                      continue;
                    }
                    try {
                      arg = ptr(args[i]).readUtf16String();
                    }
                    catch (e) {
                      continue;
                    }
                    if (arg && arg.length > 1) {
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

function hookCHostObjSleep() {
  let module = WSHOST;
  let fnName = "CHostObj::Sleep";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        call(module, fnName);
        separator();
        param("Delay", args[1].toInt32() + "ms");
        if (!ALLOW_SLEEP) {
          action("Skip");
          args[1] = ptr(0);
        }
        separator();
      }
    });
}

function hookCSWbemServicesExecQuery() {
  let module = "wbemdisp.dll";
  let fnName = "CSWbemServices::ExecQuery";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        call(module, fnName);
        separator();
        param("Query", args[1].readUtf16String());
        separator();
      }
    });
}

function hookXMLHttpOpen() {
  let module = "msxml3.dll";
  let fnName = "XMLHttp::open";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let verb = args[1].readUtf16String();
        let url = args[2].readUtf16String();

        call(module, fnName);
        separator();
        param("Verb", verb);
        param("URL", url);
        separator();
      }
    });
}

function hookXMLHttpsetRequestHeader() {
  let module = "msxml3.dll";
  let fnName = "XMLHttp::setRequestHeader";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let header = args[1].readUtf16String();
        let value = args[2].readUtf16String();

        call(module, fnName);
        separator();
        param("Header", header);
        param("Value", value);
        separator();
      }
    });
}

function hookXMLHttpSend() {
  let module = "msxml3.dll";
  let fnName = "XMLHttp::send";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        call(module, fnName);
        separator();
        try {
          let data = args[3].readUtf16String();
          if (data) {
            param("Data", data);
          }
          separator();
        }
        catch (e) {
          separator();
        }
      }
    });
}

function hookCFileSystemGetSpecialFolder() {
  const FOLDERSPEC =
  {
    0x0: "WindowsFolder",
    0x1: "SystemFolder",
    0x2: "TemporaryFolder"
  };

  let module = "scrrun.dll";
  let fnName = "CFileSystem::GetSpecialFolder";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let folder = FOLDERSPEC[args[1].toInt32()];

        call(module, fnName);
        separator();
        param("Folder", folder);
        separator();
      }
    });
}

function hookCHttpRequestOpen() {
  let module = "winhttpcom.dll";
  let fnName = "CHttpRequest::Open";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let verb = args[1].readUtf16String();
        let url = args[2].readUtf16String();

        call(module, fnName);
        separator();
        param("Verb", verb);
        param("URL", url);
        separator();
      }
    });
}

function hookCHttpRequestSetRequestHeader() {
  let module = "winhttpcom.dll";
  let fnName = "CHttpRequest::SetRequestHeader";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        let header = args[1].readUtf16String();
        let value = args[2].readUtf16String();

        call(module, fnName);
        separator();
        param("Header", header);
        param("Value", value);
        separator();
      }
    });
}

function hookCHttpRequestSend() {
  let module = "winhttpcom.dll";
  let fnName = "CHttpRequest::Send";
  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        call(module, fnName);
        separator();
        try {
          let data = args[3].readUtf16String();
          if (data) {
            param("Data", data);
          }
          separator();
        }
        catch (e) {
          separator();
        }
      }
    });
}

function hookMkParseDisplayName() {
  const MK_E_SYNTAX = 0x800401E4;
  const HRESULT =
  {
    0x00000000: "S_OK",
    0x80040154: "REGDB_E_CLASSNOTREG",
    0x80040150: "REGDB_E_READREGDB"
  };

  let module = "ole32.dll";
  let fnName = "MkParseDisplayName";

  let ptrMkParseDisplayName = Module.findExportByName(module, fnName);
  let MkParseDisplayName = new NativeFunction(ptrMkParseDisplayName, "uint", ["pointer", "pointer", "pointer", "pointer"]);

  Interceptor.replace(ptrMkParseDisplayName, new NativeCallback(function (pbc, szUserName, pchEaten, ppmk) {
    let retval = MkParseDisplayName(pbc, szUserName, pchEaten, ppmk);
    let moniker = ptr(szUserName).readUtf16String();

    call(module, fnName);
    separator();
    param("Moniker", moniker);

    /* Use ProgIDFromCLSID() to expose bad ProgIDs from CLSID. */
    let ptrCLSIDFromString = Module.findExportByName(module, "CLSIDFromString");
    let CLSIDFromString = new NativeFunction(ptrCLSIDFromString, "uint", ["pointer", "pointer"]);
    let ptrProgIDFromCLSID = Module.findExportByName(module, "ProgIDFromCLSID");
    let ProgIDFromCLSID = new NativeFunction(ptrProgIDFromCLSID, "uint", ["pointer", "pointer"]);

    const clsid_re = /(new:)(\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\})/;
    let clsid;

    if (moniker.match(clsid_re)) {
      clsid = moniker.replace(clsid_re, "$2");
      param("CLSID", clsid);

      let lpsz = Memory.allocUtf16String(clsid);
      let pclsid = Memory.alloc(16);
      let lplpszProgID = Memory.alloc(256);
      let result, szProgID;

      result = CLSIDFromString(lpsz, ptr(pclsid));
      result = ProgIDFromCLSID(pclsid, lplpszProgID);
      szProgID = ptr(lplpszProgID).readPointer().readUtf16String();

      if (HRESULT[result] === "S_OK") {
        param("ProgID", szProgID);
      }
      else {
        param("Result", HRESULT[result]);
        separator();
      }

      if (BAD_PROGIDS.has(szProgID.toLowerCase())) {
        if (!ALLOW_BAD_PROGID) {
          action("Block");
          separator();
          retval = MK_E_SYNTAX;
          return retval;
        }
      }
    }
    else if (moniker.match(/win32_process/i)) {
      if (!ALLOW_PROC) {
        action("Block");
        separator();
        retval = MK_E_SYNTAX;
        return retval;
      }
    }
    separator();
  }, "uint", ["pointer", "pointer", "pointer", "pointer"]));
}

function hookWriteLine() {
  let module = "scrrun.dll";
  let fnName = "CTextStream::WriteLine";

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        call(module, fnName);
        separator();
        writeToFile("text", ++TEXT_COUNT, ptr(args[1]).readUtf16String());
        separator();
      }
    });
}

function hookCShellDispatchNameSpace() {
  const ShellSpecialFolderConstants =
  {
    0: "%USERPROFILE%\\Desktop",
    0x2: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
    0x3: "ssfCONTROLS",
    0x4: "ssfPRINTERS",
    0x5: "%USERPROFILE%\\Documents",
    0x6: "%USERPROFILE%\\Favorites",
    0x7: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    0x8: "%APPDATA%\\Microsoft\\Windows\\Recent",
    0x9: "%APPDATA%\\Microsoft\\Windows\\SendTo",
    0xa: "ssfBITBUCKET",
    0xb: "%APPDATA%\\Microsoft\\Windows\\Start Menu",
    0x10: "%USERPROFILE%\\Desktop",
    0x11: "ssfDRIVES",
    0x12: "ssfNETWORK",
    0x13: "%APPDATA%\\Microsoft\\Windows\\Network Shortcuts",
    0x14: "%windir%\\Fonts",
    0x15: "%APPDATA%\\Microsoft\\Windows\\Templates",
    0x16: "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu",
    0x17: "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs",
    0x18: "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    0x19: "%PUBLIC%\\Desktop",
    0x1a: "%APPDATA%",
    0x1b: "%APPDATA%\\Microsoft\\Windows\\Printer Shortcuts",
    0x1c: "%LOCALAPPDATA%",
    0x1d: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    0x1e: "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    0x1f: "%USERPROFILE%\\Favorites",
    0x20: "%LOCALAPPDATA%\\Microsoft\\Windows\\INetCache",
    0x21: "%LOCALAPPDATA%\\Microsoft\\Windows\\INetCookies",
    0x22: "%LOCALAPPDATA%\\Microsoft\\Windows\\History",
    0x23: "%ALLUSERSPROFILE%",
    0x24: "%windir%",
    0x25: "%windir%\\system32",
    0x26: "%ProgramFiles%",
    0x27: "%USERPROFILE%\\Pictures",
    0x28: "%USERPROFILE%",
    0x29: "%windir%\\syswow64",
    0x30: "%SystemDrive%\\Program Files (x86)"
  };

  let module = "shell32.dll";
  let fnName = "CShellDispatch::NameSpace";
  let folder;

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        folder = ShellSpecialFolderConstants[args[3].toInt32() & 0xff];
        call(module, fnName);
        separator();
        param("Folder", folder);
        hookCFolderCopyHere(folder);
        separator();
      }
    });
}

function hookCFolderCopyHere(folder) {

  let module = "shell32.dll";
  let fnName = "CFolder::CopyHere";
  let vItem, vOptions;

  hookFunction(module, fnName,
    {
      onEnter: function (args) {
        vItem = args[3].readUtf16String();
        vOptions = args[7].toInt32() & 0xffff;
        call(module, fnName);
        separator();
        param("From", vItem);

        if (!folder.includes("ssf") && !ALLOW_FILE) {
          vItem = vItem.split("\\").slice(-1);
          const dst = folder + "\\" + vItem;
          param("To", dst);
          deleteFile(dst);
        }
        checkCopyHereOptions(vOptions);
        separator();
      },
    });
}