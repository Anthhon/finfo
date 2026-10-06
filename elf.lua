local ELF = {}

ELF.MAGICNUM = "\x7F\x45\x4C\x46"
ELF.SHT_NOBITS = 8 -- BSS section (has no data)

ELF.CLASS = {
    [1] = "32-bit",
    [2] = "64-bit"
}

ELF.DATA = {
    [1] = "little-endian",
    [2] = "big-endian"
}

ELF.ETYPE = {
    [0x00] = "NONE",
    [0x01] = "REL",
    [0x02] = "EXEC",
    [0x03] = "DYN",
    [0x04] = "CORE",
    [0xFE00] = "LOOS",
    [0xFEFF] = "HIOS",
    [0xFF00] = "LOPROC",
    [0xFFFF] = "HIPROC",
}

ELF.OSABI = {
    [0x00] = "UNIX | System V",
    [0x01] = "HP-UX",
    [0x02] = "NetBSD",
    [0x03] = "Linux",
    [0x04] = "GNU Hurd",
    [0x06] = "Solaris",
    [0x07] = "AIX (Monterey)",
    [0x08] = "IRIX",
    [0x09] = "FreeBSD",
    [0x0A] = "Tru64",
    [0x0B] = "Novell Modesto",
    [0x0C] = "OpenBSD",
    [0x0D] = "OpenVMS",
    [0x0E] = "NonStop Kernel",
    [0x0F] = "AROS",
    [0x10] = "FenixOS",
    [0x11] = "Nuxi CloudABI",
    [0x12] = "Stratus Technologies OpenVOS",
}

ELF.MACHINE = {
    [0x03] = "x86",
    [0x28] = "ARM",
    [0x3E] = "x86-64",
    [0xB7] = "AArch64",
    [0xF3] = "RISC-V"
}

-- Return table with ELF info, or nil + err reason
function ELF.parseHeader(data)
    if #data < 16 then
        return nil, "file too small for ELF identification"
    end

    if data:sub(1,4) ~= ELF.MAGICNUM then
        return nil, "bad magic number"
    end

    local class = data:byte(5)
    local endianness = data:byte(6)
    local ident_version = data:byte(7)
    local osabi = data:byte(8)
    local abi_version = data:byte(9)

    -- Treats data based on the file endianness
    local endian
    if endianness == 1 then
        endian = "<"
    elseif endianness == 2 then
        endian = ">"
    else
        return nil, "invalid ELF data encoding"
    end

    -- Gets header size based on bits data size
    local header_size
    if class == 1 then
        header_size = 52
    elseif class == 2 then
        header_size = 64
    else
        return nil, "invalid ELF class"
    end

    -- Check if header has at least the minimum size
    if #data < header_size then
        return nil, "file too small for ELF header"
    end

    -- Common fields
    local etype = string.unpack(endian .. "I2", data, 17)
    local machine = string.unpack(endian .. "I2", data, 19)
    local version = string.unpack(endian .. "I4", data, 21)

    -- Dynamic address fields
    local entry
    local phoff
    local shoff
    local flags
    local ehsize
    local phentsize
    local phnum
    local shentsize
    local shnum
    local shstrndx

    if class == 1 then
        -- ELF32
        entry = string.unpack(endian .. "I4", data, 25)
        phoff = string.unpack(endian .. "I4", data, 29)
        shoff = string.unpack(endian .. "I4", data, 33)
        flags = string.unpack(endian .. "I4", data, 37)

        ehsize = string.unpack(endian .. "I2", data, 41)
        phentsize = string.unpack(endian .. "I2", data, 43)
        phnum = string.unpack(endian .. "I2", data, 45)
        shentsize = string.unpack(endian .. "I2", data, 47)
        shnum = string.unpack(endian .. "I2", data, 49)
        shstrndx = string.unpack(endian .. "I2", data, 51) 
    elseif class == 2 then
        -- ELF64
        entry = string.unpack(endian .. "I8", data, 25)
        phoff = string.unpack(endian .. "I8", data, 33)
        shoff = string.unpack(endian .. "I8", data, 41)
        flags = string.unpack(endian .. "I4", data, 49)

        ehsize = string.unpack(endian .. "I2", data, 53)
        phentsize = string.unpack(endian .. "I2", data, 55)
        phnum = string.unpack(endian .. "I2", data, 57)
        shentsize = string.unpack(endian .. "I2", data, 59)
        shnum = string.unpack(endian .. "I2", data, 61)
        shstrndx = string.unpack(endian .. "I2", data, 63)
    end

    return {
        class = ELF.CLASS[class] or string.format("unknown (0x%02x)", class),

        data = ELF.DATA[endianness]
            or string.format("unknown (0x%02x)", endianness),

        ident_version = ident_version == 1
            and "1 (current)"
            or string.format("0x%02x", ident_version),

        osabi = ELF.OSABI[osabi]
            or string.format("unknown (0x%02x)", osabi),

        abi_version = abi_version,

        type = ELF.ETYPE[etype]
            or string.format("0x%04x", etype),

        machine = ELF.MACHINE[machine]
            or string.format("0x%04x", machine),

        version = version == 1
            and "1 (current)"
            or string.format("0x%08x", version),

        entry = entry,
        phoff = phoff,
        shoff = shoff,
        flags = flags,
        ehsize = ehsize,
        phentsize = phentsize,
        phnum = phnum,
        shentsize = shentsize,
        shnum = shnum,
        shstrndx = shstrndx,
    }
end

-- Parse section header table. Returns list of sections, or nil + err
function ELF.parseSections(data)
    local header, err = ELF.parseHeader(data)
    if not header then
        return nil, err
    end

    if header.shoff == 0 or header.shnum == 0 then
        return nil, "file has no section header table"
    end

    local class = data:byte(5)
    local endianness = data:byte(6)

    -- Get file endianness
    local endian
    if endianness == 1 then
        endian = "<"
    elseif endianness == 2 then
        endian = ">"
    else
        return nil, "invalid ELF data encoding"
    end

    -- Check for valid section header size
    local min_ent = (class == 1) and 40 or 64
    if header.shentsize < min_ent then
        return nil, "invalid section header entry size"
    end

    -- Iterates through each section
    local sections = {}
    for i = 0, header.shnum - 1 do
        local pos = header.shoff + i * header.shentsize + 1
        if pos + header.shentsize - 1 > #data then
            return nil, "section header table out of file bounds"
        end

        -- Format info to new section based on indianness
        local s = {}
        if class == 1 then
            -- ELF32 => name, type, flags, addr, offset, size (all 4 bytes)
            s.name_off, s.type, s.flags, s.addr, s.offset, s.size =
                string.unpack(endian .. "I4I4I4I4I4I4", data, pos)
        else
            -- ELF64 => name,type (4 bytes), flags,addr,offset,size (8 bytes)
            s.name_off, s.type, s.flags, s.addr, s.offset, s.size =
                string.unpack(endian .. "I4I4I8I8I8I8", data, pos)
        end

        sections[#sections + 1] = s
    end

    -- Resolve names using section-name string table
    local strtab = sections[header.shstrndx + 1]
    if not strtab then
        return nil, "invalid section name string table index"
    end
    if strtab.offset + strtab.size > #data then
        return nil, "section name string table out of file bounds"
    end

    for _, s in ipairs(sections) do
        if s.name_off >= strtab.size then
            return nil, "section name offset out of bounds"
        end
        local ok, name = pcall(string.unpack, "z", data, strtab.offset + s.name_off + 1)
        if not ok then
            return nil, "bad section name"
        end
        s.name = name
    end

    return sections
end

-- Get only ASCII printable characters
local function scanStrings(data, first, last)
    local strings, current = {}, {}
    for i = first, last do
        local byte = data:byte(i)

        if (byte >= 0x20 and byte <= 0x7E) or byte == 0x09 then
            current[#current + 1] = string.char(byte)
        else
            if #current >= 4 then -- Size threshold to be added into table
                strings[#strings + 1] = table.concat(current)
            end
            current = {}
        end
    end

    -- flush run that ends at range end
    if #current >= 4 then
        strings[#strings + 1] = table.concat(current)
    end
    return strings
end

-- target nil = scan whole file after header (old behavior)
function ELF.parseStrings(data, target)
    local response = {}
    local first, last = nil, #data

    -- Parse all sections
    local sections, err = ELF.parseSections(data)
    if not sections then
        return nil, err
    end

    -- Specified target
    if target then
        -- Search for target section into sections
        for _, s in ipairs(sections) do
            if s.name == target then
                if s.type == ELF.SHT_NOBITS then
                    return nil, "section '" .. target .. "' has no file content (NOBITS)"
                end

                -- Get strings
                first, last = s.offset + 1, s.offset + s.size
                local strings = scanStrings(data, first, last)

                -- Append target name and strings into response
                response[#response + 1] = {
                    section_name = s.name,
                    section_strings = strings
                }

                return response
            end
        end

        return nil, "section '" .. target .. "' not found" -- In case no target is found
    else -- No specific target
        for _, s in ipairs(sections) do
            -- Get strings
            first, last = s.offset + 1, s.offset + s.size
            local strings = scanStrings(data, first, last)
            if #strings > 0 then
                -- Append section name and strings into response
                response[#response + 1] = {
                    section_name = s.name,
                    section_strings = strings
                }
            end
        end

        return response
    end
end

return ELF
