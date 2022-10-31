# GootUnloader

Have you ever wondered what goes under the hood of unpacking a malicious JavaScript like [GootLoader](https://malpedia.caad.fkie.fraunhofer.de/details/js.gootloader)? Well, I certainly did when I saw Joe Sandbox [unpack](https://www.joesecurity.org/blog/4297261482537891261#) GootLoader with Microsoft's Antimalware Scan Interface (AMSI).

I present to you a tool I wrote (inspired by OALabs' [frida-wshook](https://github.com/OALabs/frida-wshook) and this blog [post](https://darungrim.com/research/2020-06-17-using-frida-for-windows-reverse-engineering.html)) that aims to do better than AMSI — GootUnloader. GootUnloader is written in Python and relying heavily on [Frida](https://frida.re), a dynamic binary instrumentation framework that enables developers, malware analysts or security researchers to have full control over a software or malware or code through function or API hooking. GootUnloader uses Frida to trace and intercept Windows Scripting Host (WSH) as it executes the malicious script. As such, it supports the analysis of script types such as `.js` (JScript) and `.vbs` (VBScript).

In theory, you should be able to use GootUnloader to analyze and unpack other malicious scripts besides GootLoader. I've tested GootUnloader against malicious scripts associated to the following malware families:

- Adwind
- AgentTesla
- AsyncRAT
- AveMariaRAT
- AZORult
- BabylonRAT
- FormBook
- GuLoader
- IcedID
- jsoutprox
- Loki
- Magniber
- NanoCore
- NetSupport
- NetWire
- NjRAT
- purecrypter
- QNodeService
- Quakbot
- RedLineStealer
- RemcosRAT
- socgholish
- STRRAT
- vjw0rm
- wshrat
- younglotus

## Features

GootUnloader has several features over AMSI when it comes to unpacking malicious scripts.

1. Unpacks the malicious script on-the-fly and writes the unpacked code to a file for further analysis and/or to extract IOCs

2. Prevents child processes from spawning when the malicious script tries to run a command or program in a new process

3. Sinkholes DNS query

4. Terminates socket
 
5. File write-protection

6. Registry write-protection

7. Terminates dangerous COM objects — only `InternetExplorer.Application` is blocklisted

8. Time skipping in `WScript.Sleep()`

9. Timestamps in output — useful for measuring time between function calls 

## Usage

To use GootUnloader, you need Python 3 and Frida:

```
pip install frida-tools
```

GootUnloader supports a number of options to disable certain protection mechanisms during analysis in order to reveal other behaviors of the malicious script that were blocked.

```
> python gootunloader.py --help
usage: gootunloader.py [-h] [-p PID | -s SCRIPT] [-o FILE] [--debug] [--disable-com] [--disable-dns] [--disable-eval]
                       [--disable-file] [--disable-net] [--disable-reg] [--disable-shell] [--disable-sleep] [--enable-timestamp]

GootUnloader - Unpack GootLoader with Frida

options:
  -h, --help            show this help message and exit
  -p PID, --pid PID     process id (reserved for future release)
  -s SCRIPT, --script SCRIPT
                        path to malicious script
  -o FILE               write output to file
  --debug               show debug output
  --disable-com         disable COM object termination
  --disable-dns         disable DNS sinkhole
  --disable-eval        disable eval() output
  --disable-file        disable file write-protect
  --disable-net         disable socket termination
  --disable-reg         disable registry write-protect
  --disable-shell       disable shell output
  --disable-sleep       disable sleep skipping
  --enable-timestamp    enable timestamp in output
```

### Supported OS

GootUnloader has been tested on Windows 10 and should work on other versions of Windows from Windows 7 onwards. 

## Feedback

If you have ideas or suggestions how to make GootUnloader better, please DM me ([@limbernie](https://twitter/limbernie)) in Twitter. Thank you!
