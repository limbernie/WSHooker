# WSHooker

Have you ever wondered what goes under the hood of unpacking a malicious JavaScript? Well, I certainly did when I saw Joe Sandbox [unpack](https://www.joesecurity.org/blog/4297261482537891261#) GootLoader with Microsoft's Antimalware Scan Interface (AMSI) during an incident response.

I present to you WSHooker, a tool I wrote (inspired by OALabs' [frida-wshook](https://github.com/OALabs/frida-wshook) and this blog [post](https://darungrim.com/research/2020-06-17-using-frida-for-windows-reverse-engineering.html)) that aims to do just as good as AMSI, if not better. WSHooker is written in Python, relying heavily on [Frida](https://frida.re), a dynamic binary instrumentation framework that enables developers, malware analysts or security researchers to have full control over a piece of software or malware or code through function or API hooking. WSHooker uses Frida to trace and intercept Windows Scripting Host (WSH) as it executes the malicious script. As such, it supports the analysis of script types such as `.js` (JScript), `.vbs` (VBScript), and even script container like `.wsf` (Windows Script File). 

In theory, you should be able to use WSHooker to analyze and unpack Windows-based malicious scripts. I've tested WSHooker against malicious scripts associated with the following malware families:

- AdWind
- AgentTesla
- AsyncRAT
- AveMariaRAT
- Azorult
- BabylonRAT
- Emotet
- Formbook
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

3. Sinkholes DNS query or terminates network socket

4. File write-protection

5. Registry write-protection

6. Terminates dangerous COM objects:
   - `InternetExplorer.Application`
   - `Schedule.Service`

7. Time skipping in `WScript.Sleep()`

8. Timestamps in output — useful for measuring time between function calls

9. Hooks functions dynamically as they are called

10. Tracks COM objects creation, `Win32_Process` creation and WMI queries.

## Usage

To use GootUnloader, you need Python 3 and Frida:

```
pip install frida-tools
```

### Setting Symbol Path

To use `c:\symbols` as the local symbol cache as GootUnloader downloads debug symbols from the Microsoft symbol server, use the following:

```
setx _NT_SYMBOL_PATH SRV*c:\symbols*https://msdl.microsoft.com/downloads/symbols
```

WSHooker may appear unresponsive on the first run as it downloads the required debug symbols. This is normal.

### Options

WSHooker supports a number of options to disable certain protection mechanisms during analysis in order to reveal other behaviors of the malicious script that were blocked.

```
python wshooker.py --help
usage: wshooker.py [-h] [-p PID | -s SCRIPT] [-a ARGS] [-o FILE] [--debug] [--disable-com] [--disable-dns]
                       [--disable-eval] [--disable-file] [--disable-net] [--disable-proc] [--disable-reg]
                       [--disable-shell] [--disable-sleep] [--enable-timestamp]

WSHooker - Windows Script Hooking with Frida

options:
  -h, --help            show this help message and exit
  -p PID, --pid PID     process id (reserved for future release)
  -s SCRIPT, --script SCRIPT
                        path to malicious script
  -a ARGS, --args ARGS  arguments to malicious script, e.g., -a "arg1 arg2 arg3 ..."
  -o FILE               write output to file
  --debug               show debug output
  --disable-com         disable COM object termination
  --disable-dns         disable DNS sinkhole
  --disable-eval        disable eval() output
  --disable-file        disable file write-protect
  --disable-net         disable socket termination
  --disable-proc        disable Win32_Process termination
  --disable-reg         disable registry write-protect
  --disable-shell       disable shell output
  --disable-sleep       disable sleep skipping
  --enable-timestamp    enable timestamp in output
```

### Supported OS

WSHooker has been tested on Windows 10.

## Feedback

If you have ideas or suggestions how to make WSHooker better, please DM me ([@limbernie](https://twitter/limbernie)) in Twitter. Thank you!
