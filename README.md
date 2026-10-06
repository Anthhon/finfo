# ƒi∩ƒ0

A small ELF file inspection tool written in Lua. Built to help with reverse engineering CTFs. May grow into a generic file analysis tool later.

## Features

- Parse ELF32 and ELF64 headers (little and big endian)
- Decode class, endianness, OS/ABI, file type, machine, entry point, program/section header info
- Hexdump (offset, hex bytes, ASCII)
- Extract printable strings from ELF sections, including `.text` and `.rodata`
- Optionally scan all string-bearing sections or target a specific one

## Requirements

Only needed to **build** finfo. The resulting binary has no Lua dependency.

- Lua 5.3 or newer (uses `string.unpack`) and its development files
- [luastatic](https://github.com/ers35/luastatic)
- [argparse](https://github.com/mpeterv/argparse) Lua library (bundled into the binary at build time)
- `gcc`

```bash
sudo apt install gcc lua5.4 liblua5.4-dev luarocks
luarocks install luastatic
luarocks install argparse
```

## Installation

Clone the repository:

```bash
git clone git@github.com:Anthhon/finfo.git
cd finfo
```

Build the standalone binary. `luastatic` takes the main script first, then every module it `require`s, then the static Lua library:

```bash
cd src
cp "$(luarocks show argparse | grep -o '/.*argparse\.lua' | head -n1)" . 2>/dev/null \
  || wget -q https://raw.githubusercontent.com/mpeterv/argparse/master/src/argparse.lua

luastatic finfo.lua elf.lua helper.lua argparse.lua \
  /usr/lib/x86_64-linux-gnu/liblua5.4.a \
  -I/usr/include/lua5.4 -lm -ldl -o ../finfo
cd ..
```

If the build cannot find the Lua library, locate it with `find /usr -name 'liblua5.4.a'` and adjust the path. If the compiler errors on line 1 of `finfo.lua`, remove the `#!/usr/bin/env lua` shebang.

Check the result:

```bash
file finfo   # ELF 64-bit executable
ldd finfo    # only libc, no liblua
```

To run it from anywhere on your machine, install it into your `PATH`:

```bash
sudo install -m 755 finfo /usr/local/bin/finfo
```

Now `finfo <file>` works from any directory. Remove with `sudo rm /usr/local/bin/finfo`.

### Running without building

You can still run it straight from source with an installed Lua interpreter:

```bash
lua src/finfo.lua <file>
```

## How to use it

You can ask for help directly to the tool by using the `-h` flag:

```bash
$ finfo -h
Usage: finfo [-h] [-a {info,hexdump}] [-s {all,text,rodata}] <file>

A simple ELF file inspection script

Arguments:
   file                  File to be inspected

Options:
   -h, --help            Show this help message and exit.
   -a, --analyze {info,hexdump}
                         Operation to perform on target file. (default: info)
   -s, --strings {all,text,rodata}
                         Get strings from executable
```

### Examples

Print ELF header info (default):

```bash
finfo /bin/ls
```

```
- class:          64-bit
- data:           little-endian
- ident version:  1 (current)
- OS/ABI:         UNIX | System V
- ABI version:    0
- type:           DYN
- machine:        x86-64
- version:        1 (current)
- entry:          0x6b10
...
```

Hexdump a file:

```bash
finfo -a hexdump /bin/ls
```

```
00000000  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  |.ELF............|
```

Extract printable strings from a binary:

```bash
finfo -s all /bin/ls
```

```text
.text
    __libc_start_main
    _start
    ...
.rodata
    /lib64/ld-linux-x86-64.so.2
    /usr/lib/locale/
    ...
```

You can also focus on a specific section:

```bash
finfo -s rodata /bin/ls
```

This walks the ELF section headers, finds the requested section, and prints printable ASCII runs at least 4 characters long. The `-s all` mode scans every section that contains readable strings; `-s text` and `-s rodata` are useful for quick reverse-engineering triage when you want to inspect the most common string-bearing sections without scanning the whole file.

Non-ELF input to `info` fails with an error (bad magic number, file too small, etc.) and exit code `2`. Unreadable file exits with `1`.

## Contributing

Contributions welcome: features, fixes, forks, whatever. Open an issue or PR.
