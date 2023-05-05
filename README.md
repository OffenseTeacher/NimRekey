# NimRekey

My experiments in improving existing anti-copy techniques

##How to use
- Install Nim on Linux
- Clone this repo
- Change values if desired, then compile Encrypt.nim
- Copy the output to NimRekey.nim and compile
- Execute it on arbitrary systems

## How to cross-compile from Linux to Windows
- "nim c -d=mingw -d=release --app=console --cpu=amd64 Encrypt.nim"
- "nim c -d=mingw -d=release --app=console --cpu=amd64 NimRekey.nim"
