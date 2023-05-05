# NimRekey
<p align="center">
    <img width="200" src="https://github.com/OffenseTeacher/NimRekey/blob/main/NimRekey.gif">
</p>
An experiment in improving existing anti-copy techniques. This one allows a binary to rewrite itself on disk after the first execution with a new key and encrypted secrets (like shellcode, URLs, etc).
Part of the key is stored in ADS, preventing the execution after copy on any other system.
For more information regarding Offensive developpment, see: [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim)

## How to use
- Install Nim on Linux
- Clone this repo
- Change values if desired, then compile Encrypt.nim
- Copy the output to NimRekey.nim and compile
- Execute it on arbitrary systems

## How to cross-compile from Linux to Windows
- "nim c -d=mingw -d=release --app=console --cpu=amd64 Encrypt.nim"
- "nim c -d=mingw -d=release --app=console --cpu=amd64 NimRekey.nim"
