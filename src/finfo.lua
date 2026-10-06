local argparse = require "argparse"
local ELF = require "elf"
local HELPER = require "helper"

-- CLI argument parsing
local parser = argparse("finfo", "A simple ELF file inspection script")
parser:argument("file", "File to be inspected")
parser:option("-a --analyze", "Operation to perform on target file.")
:choices({ "info", "hexdump" })
parser:option("-s --strings", "Get strings from executable")
:choices({ "all", "text", "rodata" })

local args = parser:parse()

io.stdout:write("\27[1m[ƒi∩ƒ0]\27[0m\n")

-- Getting file content
local content, err = HELPER.fileRead(args.file)
if not content then
    io.stderr:write("error: ", err, "\n")
    os.exit(1)
end

-- Output relevant info
io.stderr:write(("Read %d bytes from '%s'\n"):format(#content, args.file))

if args.analyze == "info" then
    local elf, err = ELF.parseHeader(content)
    if not elf then
        io.stderr:write("error: ", err, "\n")
        os.exit(2)
    end

    print("- class:          " .. elf.class)
    print("- data:           " .. elf.data)
    print("- ident version:  " .. elf.ident_version)
    print("- OS/ABI:         " .. elf.osabi)
    print("- ABI version:    " .. elf.abi_version)
    print("- type:           " .. elf.type)
    print("- machine:        " .. elf.machine)
    print("- version:        " .. elf.version)
    print("- entry:          " .. string.format("0x%x", elf.entry))
    print("- program offset: " .. string.format("0x%x", elf.phoff))
    print("- section offset: " .. string.format("0x%x", elf.shoff))
    print("- flags:          " .. string.format("0x%x", elf.flags))
    print("- header size:    " .. elf.ehsize)
    print("- program size:   " .. elf.phentsize)
    print("- program count:  " .. elf.phnum)
    print("- section size:   " .. elf.shentsize)
    print("- section count:  " .. elf.shnum)
    print("- string index:   " .. elf.shstrndx)
elseif args.strings then
    -- Specific label depending on target sections
    local section
    if args.strings == "all" then
        label = "strings:"
    else
        section = "." .. args.strings
    end

    -- Parse strings
    local response, err = ELF.parseStrings(content, section);
    if not response then
        io.stderr:write("error: ", err, "\n")
        os.exit(2)
    end

    -- Output all strings
    for _, section in ipairs(response) do
        print(section.section_name)
        if #section.section_strings == 0 then
            print("    (no strings)")
        end
        for i = 1, #section.section_strings do
            print("    " .. section.section_strings[i])
        end
    end
elseif args.analyze == "hexdump" then
    HELPER.hexDump(content)
else
    parser:parse({"--help"})
end
