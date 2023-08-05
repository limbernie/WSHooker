# WSHooker

Have you ever wondered what goes under the hood of unpacking a malicious JavaScript? Well, I certainly did when I saw Joe Sandbox [unpack](https://www.joesecurity.org/blog/4297261482537891261#) GootLoader with Microsoft's Antimalware Scan Interface (AMSI) during an investigation.

I present to you WSHooker, a tool I wrote (inspired by OALabs' [frida-wshook](https://github.com/OALabs/frida-wshook) and this blog [post](https://darungrim.com/research/2020-06-17-using-frida-for-windows-reverse-engineering.html)) that aims to do just as good as AMSI, if not better. WSHooker is written in Python, relying heavily on [Frida](https://frida.re), a dynamic binary instrumentation framework that enables developers, malware analysts or security researchers to have full control over a piece of software or malware or code through function or API hooking. WSHooker uses Frida to trace and intercept Windows Scripting Host (WSH) as it executes the malicious script. As such, it supports the analysis of script types such as `.js` (JScript), `.vbs` (VBScript), and even script container like `.wsf` (Windows Script File).

In theory, you should be able to use WSHooker to analyze and unpack malicious scripts targeted at Windows. I've tested WSHooker against malicious scripts associated with the following malware families:

- AdWind
- AgentTesla
- AsyncRAT
- AveMariaRAT
- Azorult
- BabylonRAT
- Emotet
- Formbook
- GootLoader
- GuLoader
- IcedID
- JSOutProx
- Loki
- Magniber
- NanoCore
- NetSupport
- NetWire
- NjRAT
- PureCrypter
- QNodeService
- Qbot/Qakbot/Quakbot
- RedLineStealer
- RemcosRAT
- SocGholish
- STRRAT
- Vjw0rm
- WSHRAT
- YoungLotus

## Features

WSHooker has several features over AMSI when it comes to analyzing and unpacking malicious scripts.

1. Unpacks the malicious script on-the-fly and writes the unpacked code to a file for further analysis and/or to extract IOCs

2. Prevents child processes from spawning when the malicious script tries to run a command or program in a new process

3. Sinkholes DNS query and terminates network socket

4. Prevents file copy/move/write

5. Prevents Windows Registry key/value write

6. Terminates dangerous and evasive COM objects:
   - `InternetExplorer.Application`
   - `Schedule.Service`
   - `WindowsInstaller.Installer`

7. Time skipping in `WScript.Sleep()`

8. Timestamps in output trace — useful for measuring time between function calls

9. Trace functions dynamically as they are called

10. Tracks COM objects creation, WMI queries, and stops `Win32_Process` creation 

## Usage

To use WSHooker, you need Python 3 and Frida:

```
pip install frida-tools
```

### Setting Symbol Path

To set `c:\symbols` as the local symbol cache as WSHooker downloads debug symbols from the Microsoft symbol server, use the following:

```
setx _NT_SYMBOL_PATH SRV*c:\symbols*https://msdl.microsoft.com/downloads/symbols
```

WSHooker may appear unresponsive in the first run as it downloads the required debug symbols. This is normal.

### Options

WSHooker supports a number of options to allow certain dangerous operations to continue during analysis in order to reveal behaviors of the malicious script that were otherwise blocked. 

```
python wshooker.py --help
usage: wshooker.py [-h] [-p PID | -s SCRIPT] [-a ARGS] [-o TRACE] [--allow-bad-progid] [--allow-file] [--allow-net] [--allow-proc]
                   [--allow-reg] [--allow-shell] [--allow-sleep] [--debug] [--dynamic] [--no-banner] [--timestamp] [--wscript]

WSHooker - Windows Script Hooking with Frida

options:
  -h, --help            show this help message and exit
  -p PID, --pid PID     process id (reserved for future release)
  -s SCRIPT, --script SCRIPT
                        path to malicious script
  -a ARGS, --args ARGS  arguments to malicious script, e.g., -a "arg1 arg2 arg3 ..."
  -o TRACE, --output TRACE
                        write output trace to file (default is trace.log)
  --allow-bad-progid    (dangerous) allow known bad ProgID
  --allow-file          (dangerous) allow file copy/move/write
  --allow-net           (dangerous) allow network requests
  --allow-proc          (dangerous) allow Win32_Process
  --allow-reg           (dangerous) allow registry write
  --allow-shell         (dangerous) allow shell command to run as Administrator
  --allow-sleep         (slow-down) allow WScript.Sleep()
  --debug               (verbose) display debug message
  --dynamic             (verbose) enable dynamic tracing
  --no-banner           remove banner in output trace
  --timestamp           display timestamp in output trace
  --wscript             switch to wscript.exe (default is cscript.exe)
```

### Supported OS

WSHooker has been tested on Windows 10.

## Feedback

If you have ideas or suggestions how to make WSHooker better, please DM me ([@limbernie](https://twitter.com/limbernie)) in Twitter. Thank you!
