# ƒi∩ƒ0

A small ELF file inspection tool written in Lua. Built to help with reverse engineering CTFs. May grow into a generic file analysis tool later.

## Features

- Parse ELF32 and ELF64 headers (little and big endian)
- Decode class, endianness, OS/ABI, file type, machine, entry point, program/section header info
- Hexdump (offset, hex bytes, ASCII)

## Requirements

- Lua 5.3 or newer (uses `string.unpack`)
- [argparse](https://github.com/mpeterv/argparse) Lua library

```bash
luarocks install argparse
```

## Installation

```bash
git clone <repo-url>
cd finfo
chmod +x finfo
```

And if you want to be able to execute it from anywhere in your machine easily, create a symlink:

```bash
sudo ln -s "$(pwd)/finfo" /usr/local/bin/finfo
```

Now `finfo <file>` works from any directory. Remove with `sudo rm /usr/local/bin/finfo`.

## How to use it

You can ask for help directly to the tool by using the `-h` flag:

```bash
$ ./finfo -h
Usage: finfo [-h] [-a {info,hexdump}] <file>

A simple ELF file inspection script

Arguments:
   file                  File to be inspected

Options:
   -h, --help            Show this help message and exit.
          -a {info,hexdump},
   --analyze {info,hexdump}
                         Operation to perform on target file. (default: info)
```

### Examples

Print ELF header info (default):

```bash
./finfo /bin/ls
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
./finfo -a hexdump /bin/ls
```

```
00000000  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  |.ELF............|
```

Non-ELF input to `info` fails with an error (bad magic number, file too small, etc.) and exit code `2`. Unreadable file exits with `1`.

## Contributing

Contributions welcome: features, fixes, forks, whatever. Open an issue or PR.
