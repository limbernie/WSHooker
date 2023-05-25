var DEBUG_FLAG    = false;
var DISABLE_COM   = false;
var DISABLE_DNS   = false;
var DISABLE_EVAL  = false;
var DISABLE_FILE  = false;
var DISABLE_NET   = false;
var DISABLE_PROC  = false;
var DISABLE_REG   = false;
var DISABLE_SHELL = false;
var DISABLE_SLEEP = false;
var ENABLE_DYN    = false;
var EXTENSION     = null;
var engine        = null;
var WORK_DIR      = null;
var eval_count    = 0;
var shell_count   = 0;
var sock_count    = 0;

// filter these functions from dynamic hooking
var hooked = {
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
	"CHttpRequest::Open" : 1,
	"CHttpRequest::SetRequestHeader" : 1,
	"CHttpRequest::Send" : 1,
	"CTextStream::Close" : 1,
	"CTextStream::Write" : 1,
	"CFileSystem::CopyFileA" : 1
};

recv('config', function onMessage(setting) {
	DEBUG_FLAG  = setting['debug'];
	debug(" [*] DEBUG_FLAG: " + DEBUG_FLAG);
	DISABLE_COM = setting['disable_com'];
	debug(" [*] DISABLE_COM: " + DISABLE_COM);
	DISABLE_DNS = setting['disable_dns'];
	debug(" [*] DISABLE_DNS: " + DISABLE_DNS);
	DISABLE_EVAL = setting['disable_eval'];
	debug(" [*] DISABLE_EVAL: " + DISABLE_EVAL);
	DISABLE_FILE = setting['disable_file'];
	debug(" [*] DISABLE_FILE: " + DISABLE_FILE);
	DISABLE_NET = setting['disable_net'];
	debug(" [*] DISABLE_NET: " + DISABLE_NET);
	DISABLE_PROC = setting['disable_proc'];
	debug(" [*] DISABLE_PROC: " + DISABLE_PROC);
	DISABLE_REG = setting['disable_reg'];
	debug(" [*] DISABLE_REG: " + DISABLE_REG);
	DISABLE_SHELL = setting['disable_shell'];
	debug(" [*] DISABLE_SHELL: " + DISABLE_SHELL);
	DISABLE_SLEEP = setting['disable_sleep'];
	debug(" [*] DISABLE_SLEEP: " + DISABLE_SLEEP);
	ENABLE_DYN = setting['enable_dyn'];
	debug(" [*] ENABLE_DYN: " + ENABLE_DYN);

	WORK_DIR  = setting['work_dir'];
	EXTENSION = setting['extension'];

	if (EXTENSION === 'js') {
		debug(" [*] ENGINE: JScript");
		engine = 'jscript.dll';
	} else if (EXTENSION === 'vbs') {
		debug(" [*] ENGINE: VBScript");
		engine = 'vbscript.dll';
	} else if (EXTENSION === 'wsf') {
		debug(" [*] ENGINE: Windows Script File");
	}

	// manually load these
	Module.load('jscript.dll');     // JScript Engine
	Module.load('vbscript.dll');    // VBScript Engine
	Module.load('scrrun.dll');      // Scripting Runtime
	Module.load('wshom.ocx');       // Windows Script Host Runtime
	Module.load('wbemdisp.dll');    // WMI Query Language
	Module.load('msxml3.dll');      // MSXML 3.0
	Module.load('winhttpcom.dll');  // WinHttpRequest
	Module.load('taskschd.dll');    // Schedule.Service

	// hook these
	hookCOleScriptCompile(engine);
	hookCHostObjSleep();
	hookWriteFile();
	hookCopyFileA();
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
			} catch (err) {
				return;
			}
		}
		break;
    }
}

function BytesToCLSID(address) {
	if (address.isNull())
		return;

	var data = new Uint8Array(ptr(address).readByteArray(0x10));
	var clsid = "{" + ChrToHexStr(data[3]) + ChrToHexStr(data[2]) + ChrToHexStr(data[1]) + ChrToHexStr(data[0]);
	clsid += '-' + ChrToHexStr(data[5]) + ChrToHexStr(data[4]);
	clsid += '-' + ChrToHexStr(data[7]) + ChrToHexStr(data[6]);
	clsid += '-' + ChrToHexStr(data[8]) + ChrToHexStr(data[9]);
	clsid += '-' + ChrToHexStr(data[10]) + ChrToHexStr(data[11]) + ChrToHexStr(data[12]) + ChrToHexStr(data[13]) + ChrToHexStr(data[14]) + ChrToHexStr(data[15]);
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

		debug("   [+] DebugSymbol.load " + dllName);

		try {
			DebugSymbol.load(dllName);
		} catch (err) {
			debug("   [-] DebugSymbol.load: " + err);
			return;
		}

		debug("   [+] DebugSymbol.load finished");

		if (functionName.indexOf('*') === -1) {
			try {
				debug("   [+] DebugSymbol.getFunctionByName: " + functionName);
				addr = DebugSymbol.getFunctionByName(moduleName + '!' + name);
				debug("   [+] DebugSymbol.getFunctionByName: addr = " + addr);
			} catch (err) {
				debug("   [-] DebugSymbol.getFunctionByName: " + err);
			}
		} else {
			try {
				debug("   [+] DebugSymbol.findFunctionsMatching: " + functionName);
				var addresses = DebugSymbol.findFunctionsMatching(name);
				addr = addresses[addresses.length - 1];
				debug("   [+] DebugSymbol.findFunctionsMatching: addr " + addr);
			} catch (err) {
				debug("   [-] DebugSymbol.findFunctionsMatching: " + err);
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

function hookCOleScriptCompile(engine) {
	if (engine) {
		hookFunction(engine, "COleScript::Compile", {
			onEnter: function(args) {
				log(" Call: " + engine + "!COleScript::Compile()");
				log("   |");
				if (!DISABLE_EVAL) {
					eval_count++;
					var file_path = '.\\' + WORK_DIR + '\\';
					var file_name =  'eval_' + eval_count + ".txt";
					var file = new File(file_path + file_name, 'w');
					file.write(ptr(args[1]).readUtf16String());

					log("   |-- eval(): " + "Data written to " + "'" + WORK_DIR + '\\' + file_name + "'");
					file.close();
				}
				log("   |");
				if (ENABLE_DYN) hookDispCallFunc();
				hookCLSIDFromProgID();
			}
		});
	} else {
		// we need to hook COleScript::Compile for both js and vbs
		hookCOleScriptCompileAll();
	}
}

function hookCOleScriptCompileAll() {
	hookFunction("jscript.dll", "COleScript::Compile", {
		onEnter: function(args) {
			log(" Call: " + "jscript.dll" + "!COleScript::Compile()");
			log("   |");
			if (!DISABLE_EVAL) {
				eval_count++;
				var file_path = '.\\' + WORK_DIR + '\\';
				var file_name =  'eval_' + eval_count + ".txt";
				var file = new File(file_path + file_name, 'w');
				file.write(ptr(args[1]).readUtf16String());

				log("   |-- eval(): " + "Data written to " + "'" + WORK_DIR + '\\' + file_name + "'");
				file.close();
			}
			log("   |");
			if (ENABLE_DYN) hookDispCallFunc();
			hookCLSIDFromProgID();
		}
	});

	hookFunction("vbscript.dll", "COleScript::Compile", {
		onEnter: function(args) {
			log(" Call: " + "vbscript.dll" + "!COleScript::Compile()");
			log("   |");
			if (!DISABLE_EVAL) {
				eval_count++;
				var file_path = '.\\' + WORK_DIR + '\\';
				var file_name =  'eval_' + eval_count + ".txt";
				var file = new File(file_path + file_name, 'w');
				file.write(ptr(args[1]).readUtf16String());

				log("   |-- eval(): " + "Data written to " + "'" + WORK_DIR + '\\' + file_name + "'");
				file.close();
			}
			log("   |");
			if (ENABLE_DYN) hookDispCallFunc();
			hookCLSIDFromProgID();
		}
	});
}

var WSAHOST_NOT_FOUND = 11001;

function hookGetAddrInfoExW() {
	var host = '';
	hookFunction('ws2_32.dll', "GetAddrInfoExW", {
		onEnter: function(args) {
			log(" Call: ws2_32.dll!GetAddrInfoExW()");
			log("   |");
			host = args[0].readUtf16String();
			log("   |-- Query: " + host);
		},
		onLeave: function(retval) {
			if (!DISABLE_DNS) {
				log("   |-- (Sinkholed!)");
				retval.replace(WSAHOST_NOT_FOUND);
			}
			log("   |");
		}
	});
}

function hookWSASend() {
	hookFunction('ws2_32.dll', 'WSASend', {
		onEnter: function(args) {
			log(" Call: ws2_32.dll!WSASend()");
			log("   |");
			log("   |-- Socket : " + args[0]);
			log("   |-- Buffers: " + args[2].toInt32());
			var size = ptr(args[1]).readInt();
			log("   |-- Size   : " + size);

			if (!DISABLE_NET) {
				sock_count++;
				var lpwbuf = args[1].toInt32() + 4;
				var dptr = Memory.readInt(ptr(lpwbuf));
				var data = hexdump(ptr(dptr), { length: size });

				var file_path = '.\\' + WORK_DIR + '\\';
				var file_name =  'sock_' + sock_count + ".txt";
				var file = new File(file_path + file_name, 'w');
				file.write(data);

				log("   |-- Data   : " + "Data written to " + "'" + WORK_DIR + '\\' + file_name + "'");
				file.close();

				var ptr_closesocket = Module.findExportByName("ws2_32.dll", "closesocket");
				var closesocket = new NativeFunction(ptr_closesocket, 'int', ['pointer']);
				closesocket(args[0]);
				log("   |-- (Socket terminated!)");
			}
			log("   |");
		}
	});
}

function hookShellExecuteExW() {
	hookFunction('shell32.dll', "ShellExecuteExW", {
		onEnter: function(args) {
			log(" Call: shell32.dll!ShellExecuteExW()");
			log("   |");
			var shellinfo_ptr = args[0];
			var ptr_file = Memory.readPointer(shellinfo_ptr.add(16));
			var ptr_params = Memory.readPointer(shellinfo_ptr.add(20));
			var lpfile = Memory.readUtf16String(ptr(ptr_file));
			var lpparams = Memory.readUtf16String(ptr(ptr_params));

			if (!DISABLE_SHELL) {
				shell_count++
				var file_path = '.\\' + WORK_DIR + '\\';
				var file_name = 'shell_' + shell_count + ".txt";
				var file = new File(file_path + file_name, 'w');
				file.write("Command: " + lpfile);
				file.write("\n");
				file.write("Params : " + lpparams);
				log("   |-- Shell: " + "Data written to " + "'" + WORK_DIR + '\\' + file_name + "'");
				file.close();
			}
		log("   |");
		}
	});
}

function hookCWshShellRegWrite() {
	hookFunction('wshom.ocx', "CWshShell::RegWrite", {
		onEnter: function(args) {
			log(" Call: wshom.ocx!CWshShell::RegWrite()");
			log("   |");
			var path = args[1].readUtf16String();

			if (path.slice(-1) == '\\') {
				log("   |-- Key: " + path);
				if (!DISABLE_REG) deleteKey(path);
			}
			else {
				log("   |-- Value: " + path);
				if (!DISABLE_REG) deleteValue(path);
			}
			log("   |");
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
			log(" Call: kernel32.dll!WriteFile()");
			log("   |");
			var handle = args[0];
			log("   |-- Handle: " + handle);
			var size = args[2].toInt32();
			log("   |-- Size  : " + size);

			var ptrGetFinalPathNameByHandleW = Module.findExportByName('kernel32.dll', 'GetFinalPathNameByHandleW');
			var GetFinalPathNameByHandleW = new NativeFunction(
												ptrGetFinalPathNameByHandleW,
												'int', ['pointer', 'pointer', 'int', 'int']);

			var lpszFilePath = Memory.alloc(256);
			GetFinalPathNameByHandleW(handle, ptr(lpszFilePath), 256, 0x8);
			var path = lpszFilePath.readUtf16String();
			log("   |-- Path  : " + path);
			if (!DISABLE_FILE) deleteFile(path);
			log("   |");
		}
	});
}

function hookCopyFileA() {
	hookFunction('scrrun.dll', "CFileSystem::CopyFileA", {
		onEnter: function(args) {
			log(" Call: scrrun.dll!CFileSystem::CopyFileA()");
			log("   |");
			var src = args[1].readUtf16String();
			var dst = args[2].readUtf16String();
			log("   |-- Source: " + src);
			log("   |-- Destination: " + dst);
			if (!DISABLE_FILE) deleteFile(dst);
			log("   |");
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
var badCOM = {
	"internetexplorer.application" : 1,
	"schedule.service" : 1
};

function hookCLSIDFromProgID() {
	var ptrCLSIDFromProgID = Module.findExportByName('ole32.dll', "CLSIDFromProgID");
	var CLSIDFromProgID = new NativeFunction(ptrCLSIDFromProgID, 'uint', ['pointer', 'pointer']);
	Interceptor.replace(ptrCLSIDFromProgID, new NativeCallback(function (lpszProgID, lpclsid) {
		var retval = CLSIDFromProgID(lpszProgID, lpclsid);
		var progid = lpszProgID.readUtf16String();
		var clsid  = BytesToCLSID(ptr(lpclsid))
		log(" Call: ole32.dll!CLSIDFromProgID()");
		log("   |");
		log("   |-- ProgID: " + progid);
		log("   |-- CLSID : " + clsid);
		getInprocServer32(clsid);

		if (progid.toLowerCase() in badCOM) {
			if (!DISABLE_COM) {
				log("   |-- (Dangerous COM object terminated!)");
				retval = CO_E_CLASSSTRING;
			}
		}
		log("   |");
		return retval;
	}, 'uint', ['pointer', 'pointer'], 'stdcall'));
}

function hookDispCallFunc() {
	if (!("DispCallFunc" in hooked)) {
		hooked["DispCallFunc"] = 1;
		var ptrDispCallFunc = Module.findExportByName('oleaut32.dll', "DispCallFunc");
		Interceptor.attach(ptrDispCallFunc, {
			onEnter: function(args) {
				log(" Call: oleaut32.dll!DispCallFunc()");
				log("   |");
				var pvInstance = args[0];
				var oVft = args[1];
				var instance = ptr(ptr(pvInstance).readULong());
				var vftbPtr = instance.add(oVft);
				var functionAddress = ptr(ptr(vftbPtr).readULong());

				loadModuleForAddress(functionAddress)
				var functionName = DebugSymbol.fromAddress(functionAddress)
				log("   |-- Function: " + functionName);
				log("   |");

				// hook new functions here if they aren't already hooked
				if (!(functionName.name in hooked)) {
					hooked[functionName.name] = 1;
					Interceptor.attach(functionAddress, {
						onEnter: function(args) {
							log(" Call: " + functionName.moduleName + '!' + functionName.name + '()');
							log("   |");
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
								if (out) log("   |-- Arg: " + out);
							}
							log("   |");
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
	0x80070057 : "E_INVALIDARG"
};

function hookCHostObjSleep() {
	hookFunction('wscript.exe', "CHostObj::Sleep", {
		onEnter: function(args) {
			log(" Call: wscript.exe!CHostObj::Sleep()");
			log("   |");
			log("   |-- intTime: " + args[1].toInt32() + "ms" +
				(DISABLE_SLEEP ? "" : " (Skipping to 0ms)"));
			if (!DISABLE_SLEEP)
				args[1] = ptr(0x0);
		},
		onLeave(retval) {
			log("   |-- HRESULT: " + HRESULT[retval.toInt32()]);
			log("   |");

		}
	});
}

function hookCSWbemServicesExecQuery() {
	hookFunction('wbemdisp.dll', 'CSWbemServices::ExecQuery', {
		onEnter: function(args) {
			log(" Call: wbemdisp.dll!CSWbemServices::ExecQuery()");
			log("   |");
			log("   |-- Query: " + args[1].readUtf16String());
			log("   |");
		}
	});
}

function hookXMLHttpOpen() {
	hookFunction('msxml3.dll', 'XMLHttp::open', {
		onEnter: function(args) {
			log(" Call: msxml3.dll!XMLHttp::open()");
			log("   |");
			var verb = args[1].readUtf16String();
			var url  = args[2].readUtf16String();
			log("   |-- Verb: " + verb);
			log("   |-- URL : " + url);
			log("   |");
		}
	});
}

function hookXMLHttpsetRequestHeader() {
	hookFunction('msxml3.dll', 'XMLHttp::setRequestHeader', {
		onEnter: function(args) {
			log(" Call: msxml3.dll!XMLHttp::setRequestHeader()");
			log("   |");
			var header = args[1].readUtf16String();
			var value  = args[2].readUtf16String();
			log("   |-- Header: " + header);
			log("   |-- Value : " + value);
			log("   |");
		}
	});
}

function hookXMLHttpSend() {
	hookFunction('msxml3.dll', 'XMLHttp::send', {
		onEnter: function(args) {
			log(" Call: msxml3.dll!XMLHttp::send()");
			log("   |");
			try {
				var data = args[3].readUtf16String();
				if (data)
					log("   |-- Data: " + data);
			} catch(e) {}
			log("   |");
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
			log(" Call: scrrun.dll!CFileSystem::GetSpecialFolder()");
			log("   |");
			log("   |-- Folder: " + args[1] + " (" + FOLDERSPEC[args[1].toInt32()] + ")");
			log("   |");
		}
	});
}

function hookCHttpRequestOpen() {
	hookFunction('winhttpcom.dll', 'CHttpRequest::Open', {
		onEnter: function(args) {
			log(" Call: winhttpcom.dll!CHttpRequest::Open()");
			log("   |");
			var verb = args[1].readUtf16String();
			var url  = args[2].readUtf16String();
			log("   |-- Verb: " + verb);
			log("   |-- URL : " + url);
			log("   |");
		}
	});
}

function hookCHttpRequestSetRequestHeader() {
	hookFunction('winhttpcom.dll', 'CHttpRequest::SetRequestHeader', {
		onEnter: function(args) {
			log(" Call: winhttpcom.dll!CHttpRequest::SetRequestHeader()");
			log("   |");
			var header = args[1].readUtf16String();
			var value  = args[2].readUtf16String();
			log("   |-- Header: " + header);
			log("   |-- Value : " + value);
			log("   |");
		}
	});
}

function hookCHttpRequestSend() {
	hookFunction('winhttpcom.dll', 'CHttpRequest::Send', {
		onEnter: function(args) {
			log(" Call: winhttpcom.dll!CHttpRequest::Send()");
			log("   |");
			try {
				var data = args[3].readUtf16String();
				if (data)
					log("   |-- Data: " + data);
			} catch(e) {}
			log("   |");
		}
	});
}

var MK_E_SYNTAX = 0x800401E4;

function hookMkParseDisplayName() {
	var moniker = null;
	hookFunction('ole32.dll', "MkParseDisplayName", {
		onEnter: function(args) {
			moniker = args[1].readUtf16String();
			log(" Call: ole32.dll!MkParseDisplayName()");
			log("   |");
			log("   |-- Object: " + moniker);
		},
		onLeave(retval) {
			if (!DISABLE_PROC)
				if (moniker.match(/win32_process/i)) {
					log("   |-- Win32_Process (blocked!)");
					retval.replace(MK_E_SYNTAX);
				}
			log("   |");
		}
	});
}